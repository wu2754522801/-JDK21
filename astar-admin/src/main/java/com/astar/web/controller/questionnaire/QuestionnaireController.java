package com.astar.web.controller.questionnaire;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import com.astar.common.annotation.Log;
import com.astar.common.core.controller.BaseController;
import com.astar.common.core.domain.AjaxResult;
import com.astar.common.core.page.TableDataInfo;
import com.astar.common.enums.BusinessType;
import com.astar.common.utils.poi.ExcelUtil;
import com.astar.questionnaire.constant.FormConstant;
import com.astar.questionnaire.domain.TbQuestionnaire;
import com.astar.questionnaire.domain.TbQuestionnaireUser;
import com.astar.questionnaire.domain.vo.KeyValueDTO;
import com.astar.questionnaire.domain.vo.QsFillVO;
import com.astar.questionnaire.service.ITbQuestionnaireService;
import com.astar.questionnaire.service.ITbQuestionnaireUserService;
import jakarta.servlet.http.HttpServletResponse;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.apache.commons.lang3.ObjectUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

/**
 * 问卷调查管理Controller
 *
 * @author astar
 * @date 2024-03-01
 */
@RestController
@RequestMapping("/questionnaire")
public class QuestionnaireController extends BaseController {
  @Autowired private ITbQuestionnaireService tbQuestionnaireService;
  @Autowired private ITbQuestionnaireUserService tbQuestionnaireUserService;

  public static void findLabel(JSONArray options, int targetValue) {
    Optional<JSONObject> option =
        options.stream()
            .map(JSONObject.class::cast)
            .filter(o -> o.getInteger(FormConstant.FORM_VALUE) == targetValue)
            .findFirst();

    option.ifPresent(
        o -> {
          System.out.println(o.getString(FormConstant.FORM_LABEL));
          if (o.containsKey("children")) {
            findLabel(o.getJSONArray("children"), targetValue);
          }
        });
  }

  /** 查询问卷调查管理列表 */
  @PreAuthorize("@ss.hasPermi('system:questionnaire:list')")
  @GetMapping("/list")
  public TableDataInfo list(TbQuestionnaire tbQuestionnaire) {
    startPage();
    List<TbQuestionnaire> list = tbQuestionnaireService.selectTbQuestionnaireList(tbQuestionnaire);
    return getDataTable(list);
  }

  /** 导出问卷调查管理列表 */
  @PreAuthorize("@ss.hasPermi('system:questionnaire:export')")
  @Log(title = "问卷调查管理", businessType = BusinessType.EXPORT)
  @PostMapping("/export")
  public void export(HttpServletResponse response, TbQuestionnaire tbQuestionnaire) {
    List<TbQuestionnaire> list = tbQuestionnaireService.selectTbQuestionnaireList(tbQuestionnaire);
    ExcelUtil<TbQuestionnaire> util = new ExcelUtil<TbQuestionnaire>(TbQuestionnaire.class);
    util.exportExcel(response, list, "问卷调查管理数据");
  }

  /** 获取问卷调查管理详细信息 */
  @PreAuthorize("@ss.hasPermi('system:questionnaire:query')")
  @GetMapping(value = "/{id}")
  public AjaxResult getInfo(@PathVariable("id") Long id) {
    return success(tbQuestionnaireService.selectTbQuestionnaireById(id));
  }

  /** 新增问卷调查管理 */
  @PreAuthorize("@ss.hasPermi('system:questionnaire:add')")
  @Log(title = "问卷调查管理", businessType = BusinessType.INSERT)
  @PostMapping
  public AjaxResult add(@RequestBody TbQuestionnaire tbQuestionnaire) {
    return toAjax(tbQuestionnaireService.insertTbQuestionnaire(tbQuestionnaire));
  }

  /** 修改问卷调查管理 */
  @PreAuthorize("@ss.hasPermi('system:questionnaire:edit')")
  @Log(title = "问卷调查管理", businessType = BusinessType.UPDATE)
  @PutMapping
  public AjaxResult edit(@RequestBody TbQuestionnaire tbQuestionnaire) {
    return toAjax(tbQuestionnaireService.updateTbQuestionnaire(tbQuestionnaire));
  }

  /** 删除问卷调查管理 */
  @PreAuthorize("@ss.hasPermi('system:questionnaire:remove')")
  @Log(title = "问卷调查管理", businessType = BusinessType.DELETE)
  @DeleteMapping("/{ids}")
  public AjaxResult remove(@PathVariable Long[] ids) {
    return toAjax(tbQuestionnaireService.deleteTbQuestionnaireByIds(ids));
  }

  /** 发布 */
  @PreAuthorize("@ss.hasPermi('system:questionnaire:publish')")
  @Log(title = "问卷调查管理", businessType = BusinessType.UPDATE)
  @PutMapping("/publish")
  public AjaxResult publish(@RequestBody TbQuestionnaire tbQuestionnaire) {
    return toAjax(tbQuestionnaireService.publish(tbQuestionnaire));
  }

  /**
   * 问卷填报管理
   *
   * @param entity
   * @return {@link QsFillVO}
   */
  @GetMapping("/qsFillManage")
  public QsFillVO qsFillManage(TbQuestionnaire entity) {
    // 查询问卷配置
    TbQuestionnaire tbQuestionnaire =
        tbQuestionnaireService.selectTbQuestionnaireById(entity.getId());
    // 查询填报信息
    startPage();
    TbQuestionnaireUser questionnaireUser = new TbQuestionnaireUser();
    questionnaireUser.setQsId(entity.getId());
    List<TbQuestionnaireUser> list =
        tbQuestionnaireUserService.selectTbQuestionnaireUserList(questionnaireUser);
    TableDataInfo dataTable = getDataTable(list);
    // 返回数据
    QsFillVO vo = new QsFillVO();
    vo.setCode(dataTable.getCode());
    vo.setTotal(dataTable.getTotal());
    vo.setMsg(dataTable.getMsg());
    // 获取表单配置
    String formJson = tbQuestionnaire.getFormJson();
    JSONObject jsonObject = JSON.parseObject(formJson);
    JSONArray jsonArray = jsonObject.getJSONArray(FormConstant.FORM_FIELDS);
    List<KeyValueDTO> titleList =
        jsonArray.stream()
            .map(v -> (JSONObject) v)
            .map(
                v -> {
                  KeyValueDTO dto = new KeyValueDTO();
                  String type = v.getString(FormConstant.FORM_TYPE);
                  String key = v.getString(FormConstant.FORM_KEY);
                  String label =
                      v.getJSONObject(FormConstant.FORM_CONFIG).getString(FormConstant.FORM_LABEL);
                  dto.setKey(key);
                  dto.setType(type);
                  dto.setLabel(label);
                  if (FormConstant.FORM_TYPE_CASCADER.equals(type)) {
                    JSONArray options = v.getJSONArray(FormConstant.FORM_OPTIONS);
                    dto.setOptions(options);
                  } else if (FormConstant.FORM_TYPE_SELECT.equals(type)
                      || FormConstant.FORM_TYPE_RADIO.equals(type)
                      || FormConstant.FORM_TYPE_CHECKBOX.equals(type)) {
                    JSONObject slot = v.getJSONObject(FormConstant.FORM_SLOT);
                    JSONArray options = slot.getJSONArray(FormConstant.FORM_OPTIONS);
                    dto.setOptions(options);
                  }
                  return dto;
                })
            .collect(Collectors.toList());
    KeyValueDTO dto = new KeyValueDTO();
    dto.setKey("createdTime");
    dto.setType("createdTime");
    dto.setLabel("填报时间");
    titleList.add(0, dto);
    vo.setTitleList(titleList);
    // 组装问卷值
    List<TbQuestionnaireUser> rows = (List<TbQuestionnaireUser>) dataTable.getRows();
    if (rows.size() <= 0) {
      return vo;
    }
    Map<String, KeyValueDTO> keyTypeMap =
        titleList.stream().collect(Collectors.toMap(KeyValueDTO::getKey, Function.identity()));
    List<Map<String, Object>> dataList =
        rows.stream()
            .map(
                data -> {
                  JSONObject v = JSON.parseObject(data.getDataJson());
                  Map<String, Object> dataMap = new HashMap<>(v.size());
                  // 遍历所有key
                  Iterator<Map.Entry<String, Object>> iterator = v.entrySet().iterator();
                  while (iterator.hasNext()) {
                    Map.Entry<String, Object> next = iterator.next();
                    String key = next.getKey();
                    Object value = next.getValue();
                    KeyValueDTO keyValueDTO = keyTypeMap.get(key);
                    Object dataValue =
                        getValue(key, keyValueDTO.getType(), value, keyValueDTO.getOptions());
                    dataMap.put(key, dataValue);
                  }
                  dataMap.put("createdTime", data.getCreatedTime().toString().replace("T", " "));
                  return dataMap;
                })
            .collect(Collectors.toList());
    vo.setRows(dataList);
    return vo;
  }

  /**
   * 获取值
   *
   * @param key 字段key
   * @param fieldType 字段类型
   * @param valueObj 值
   * @return {@link Object}
   */
  private Object getValue(String key, String fieldType, Object valueObj, JSONArray options) {
    if (ObjectUtils.isEmpty(valueObj)) {
      return valueObj;
    }
    switch (fieldType) {
      case FormConstant.FORM_TYPE_INPUT:
        break;
      case FormConstant.FORM_TYPE_TEXTAREA:
        break;
      case FormConstant.FORM_TYPE_PASSWORD:
        break;
      case FormConstant.FORM_TYPE_STEP:
        break;
      case FormConstant.FORM_TYPE_EDITOR:
        break;
      case FormConstant.FORM_TYPE_SELECT:
        String valueStr = valueObj.toString();
        valueObj =
            options.stream()
                .map(v -> (JSONObject) v)
                .filter(v -> v.getString(FormConstant.FORM_VALUE).equals(valueStr))
                .map(v -> v.getString(FormConstant.FORM_LABEL))
                .collect(Collectors.joining(","));
        break;
      case FormConstant.FORM_TYPE_CASCADER:
        JSONArray field106 = JSON.parseArray(JSON.toJSONString(valueObj));
        List<String> data = new ArrayList<>();
        for (int i = 0; i < field106.size(); i++) {
          int value = field106.getInteger(i);
          Optional<JSONObject> first =
              options.stream()
                  .map(JSONObject.class::cast)
                  .filter(o -> o.getInteger(FormConstant.FORM_VALUE) == value)
                  .findFirst();
          boolean present = first.isPresent();
          if (present) {
            JSONObject o = first.get();
            data.add(o.getString(FormConstant.FORM_LABEL));
            if (o.containsKey("children")) {
              options = o.getJSONArray("children");
            }
          }
        }
        valueObj = data.stream().collect(Collectors.joining("/"));
        break;
      case FormConstant.FORM_TYPE_RADIO:
        String radioValue = valueObj.toString();
        valueObj =
            options.stream()
                .map(v -> (JSONObject) v)
                .filter(v -> v.getString(FormConstant.FORM_VALUE).equals(radioValue))
                .map(v -> v.getString(FormConstant.FORM_LABEL))
                .collect(Collectors.joining(","));
        break;
      case FormConstant.FORM_TYPE_CHECKBOX:
        List<String> checkBoxList = JSON.parseArray(JSON.toJSONString(valueObj), String.class);
        valueObj =
            options.stream()
                .map(v -> (JSONObject) v)
                .filter(v -> checkBoxList.contains(v.getString(FormConstant.FORM_VALUE)))
                .map(v -> v.getString(FormConstant.FORM_LABEL))
                .collect(Collectors.joining(","));
        break;
      case FormConstant.FORM_TYPE_SWITCH:
        break;
      case FormConstant.FORM_TYPE_SLIDER:
        break;
      case FormConstant.FORM_TYPE_TIME:
        break;
      case FormConstant.FORM_TYPE_TIMERANGE:
        // 拼接
        JSONArray timeRange = JSON.parseArray(JSON.toJSONString(valueObj));
        valueObj = timeRange.get(0) + "至" + timeRange.get(1);
        break;
      case FormConstant.FORM_TYPE_DATE:
        break;
      case FormConstant.FORM_TYPE_DATERANGE:
        // 拼接
        JSONArray dateRange = JSON.parseArray(JSON.toJSONString(valueObj));
        valueObj = dateRange.get(0) + "至" + dateRange.get(1);
        break;
      case FormConstant.FORM_TYPE_RATE:
        break;
      case FormConstant.FORM_TYPE_COLOR:
        break;
      case FormConstant.FORM_TYPE_UPLOAD:
        break;
      default:
        valueObj = "未找到";
    }
    return valueObj;
  }
}
