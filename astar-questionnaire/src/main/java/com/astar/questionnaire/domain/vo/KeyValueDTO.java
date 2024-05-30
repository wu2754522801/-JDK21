package com.astar.questionnaire.domain.vo;

import com.alibaba.fastjson2.JSONArray;
import lombok.Data;

import java.util.Map;

/**
 * @author wuzhenyong
 * ClassName:KeyValueDTO.java
 * date:2024-03-02 14:54
 * Description:
 */
@Data
public class KeyValueDTO {
    private String key;
    private String type;
    private String label;
    // 选项
    private JSONArray options;
}
