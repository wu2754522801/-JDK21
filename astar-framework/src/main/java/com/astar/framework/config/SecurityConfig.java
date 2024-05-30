package com.astar.framework.config;

import static org.springframework.security.config.Customizer.withDefaults;

import com.astar.framework.config.properties.PermitAllUrlProperties;
import com.astar.framework.security.filter.JwtAuthenticationTokenFilter;
import com.astar.framework.security.handle.AuthenticationEntryPointImpl;
import com.astar.framework.security.handle.LogoutSuccessHandlerImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.filter.CorsFilter;

/**
 * spring security配置
 *
 * @author astar
 */
@Configuration
@EnableMethodSecurity(securedEnabled = true)
// @EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurityConfig {
  /** 自定义用户认证逻辑 */
  @Autowired private UserDetailsService userDetailsService;

  /** 认证失败处理类 */
  @Autowired private AuthenticationEntryPointImpl unauthorizedHandler;

  /** 退出处理类 */
  @Autowired private LogoutSuccessHandlerImpl logoutSuccessHandler;

  /** token认证过滤器 */
  @Autowired private JwtAuthenticationTokenFilter authenticationTokenFilter;

  /** 跨域过滤器 */
  @Autowired private CorsFilter corsFilter;

  /** 允许匿名访问的地址 */
  @Autowired private PermitAllUrlProperties permitAllUrl;

  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
      throws Exception {
    DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
    // 将编写的UserDetailsService注入进来
    provider.setUserDetailsService(userDetailsService);
    // 将使用的密码编译器加入进来
    provider.setPasswordEncoder(passwordEncoder());
    // 将provider放置到AuthenticationManager 中
    return new ProviderManager(provider);
  }

  /** 强散列哈希加密实现 */
  @Bean
  public BCryptPasswordEncoder bCryptPasswordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return bCryptPasswordEncoder();
  }

  @Bean
  public UserDetailsService userDetailsService() {
    // 调用 JwtUserDetailService实例执行实际校验
    return username -> userDetailsService.loadUserByUsername(username);
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    // 注解标记允许匿名访问的url
    // http.authorizeRequests(registry ->registry.requestMatchers(url) );
    permitAllUrl
        .getUrls()
        .forEach(
            url -> {
              try {
                http.authorizeHttpRequests(registry -> registry.requestMatchers(url).permitAll());
              } catch (Exception e) {
                // 忽略.
                e.printStackTrace();
              }
            });

    http
        // CSRF禁用，因为不使用session
        .csrf(AbstractHttpConfigurer::disable)
        // 禁用HTTP响应标头
        .headers(
            (headers) ->
                headers
                    .cacheControl(HeadersConfigurer.CacheControlConfig::disable)
                    .frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
        .exceptionHandling(withDefaults())
        .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(unauthorizedHandler))
        // 前后端分离是无状态的，不需要session了，直接禁用。
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(
            authorizeHttpRequests ->
                authorizeHttpRequests
                    .requestMatchers(
                        "/login", "/register", "/captchaImage", "/questionnaire/write/**")
                    .permitAll()
                    // 静态资源，可匿名访问
                    .requestMatchers(
                        HttpMethod.GET, "/", "/**.html", "/**.css", "/**.js", "/profile/**")
                    .permitAll()
                    .requestMatchers(
                        "/swagger-ui.html",
                        "/swagger-resources/**",
                        "/webjars/**",
                        "/*/api-docs",
                        "/druid/**")
                    .permitAll()
                    // 除上面外的所有请求全部需要鉴权认证
                    .anyRequest()
                    .authenticated())
        // 添加Logout filter
        .logout(
            (logout) ->
                logout
                    .deleteCookies("remove")
                    .invalidateHttpSession(false)
                    .logoutUrl("/logout")
                    .logoutSuccessHandler(logoutSuccessHandler))
        .httpBasic(withDefaults());
    // 添加JWT filter
    http.addFilterBefore(authenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);
    // 添加CORS filter
    http.addFilterBefore(corsFilter, JwtAuthenticationTokenFilter.class);
    http.addFilterBefore(corsFilter, LogoutFilter.class);
    return http.build();
  }
}
