package com.astar.web.controller.questionnaire;

import com.astar.common.annotation.Anonymous;
import com.astar.common.annotation.Log;
import com.astar.common.core.controller.BaseController;
import com.astar.common.core.domain.AjaxResult;
import com.astar.common.core.page.TableDataInfo;
import com.astar.common.enums.BusinessType;
import com.astar.common.utils.ip.IpUtils;
import com.astar.common.utils.poi.ExcelUtil;
import com.astar.questionnaire.domain.TbQuestionnaire;
import com.astar.questionnaire.domain.TbQuestionnaireUser;
import com.astar.questionnaire.service.ITbQuestionnaireService;
import com.astar.questionnaire.service.ITbQuestionnaireUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletResponse;
import java.util.List;

/**
 * 问卷调查管理Controller
 * 
 * @author astar
 * @date 2024-03-01
 */
@Anonymous
@RestController
@RequestMapping("/qs")
public class QsController extends BaseController
{
    @Autowired
    private ITbQuestionnaireService tbQuestionnaireService;
    @Autowired
    private ITbQuestionnaireUserService tbQuestionnaireUserService;

    /**
     * 获取问卷配置
     * @param url
     * @return {@link AjaxResult}
     */
    @GetMapping("/getQs/{url}")
    public AjaxResult getQs(@PathVariable("url") String url)
    {
        return success(tbQuestionnaireService.getQs(url));
    }
    /**
     * 新增填写问卷管理
     */
    @Log(title = "填写问卷管理", businessType = BusinessType.INSERT)
    @PostMapping("/fillQs")
    public AjaxResult fillQs(@RequestBody TbQuestionnaireUser tbQuestionnaireUser)
    {
        tbQuestionnaireUser.setIpAddr(IpUtils.getIpAddr());
        return toAjax(tbQuestionnaireUserService.insertTbQuestionnaireUser(tbQuestionnaireUser));
    }
}
