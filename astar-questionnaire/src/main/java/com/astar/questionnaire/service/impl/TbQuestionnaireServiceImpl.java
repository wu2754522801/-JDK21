package com.astar.questionnaire.service.impl;

import java.util.List;

import com.astar.common.config.AstarConfig;
import com.astar.common.utils.SecurityUtils;
import com.astar.common.utils.StringUtils;
import com.astar.questionnaire.domain.TbQuestionnaireUser;
import com.astar.questionnaire.domain.vo.QsFillVO;
import com.astar.questionnaire.mapper.TbQuestionnaireUserMapper;
import com.astar.questionnaire.utils.ShortUrlUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.astar.questionnaire.mapper.TbQuestionnaireMapper;
import com.astar.questionnaire.domain.TbQuestionnaire;
import com.astar.questionnaire.service.ITbQuestionnaireService;
import org.springframework.util.StreamUtils;

/**
 * 问卷调查管理Service业务层处理
 * 
 * @author astar
 * @date 2024-03-01
 */
@Service
public class TbQuestionnaireServiceImpl implements ITbQuestionnaireService 
{
    @Autowired
    private TbQuestionnaireMapper tbQuestionnaireMapper;
    @Autowired
    private TbQuestionnaireUserMapper tbQuestionnaireUserMapper;

    /**
     * 查询问卷调查管理
     * 
     * @param id 问卷调查管理主键
     * @return 问卷调查管理
     */
    @Override
    public TbQuestionnaire selectTbQuestionnaireById(Long id)
    {
        return tbQuestionnaireMapper.selectTbQuestionnaireById(id);
    }

    /**
     * 查询问卷调查管理列表
     * 
     * @param tbQuestionnaire 问卷调查管理
     * @return 问卷调查管理
     */
    @Override
    public List<TbQuestionnaire> selectTbQuestionnaireList(TbQuestionnaire tbQuestionnaire)
    {
        List<TbQuestionnaire> tbQuestionnaires = tbQuestionnaireMapper.selectTbQuestionnaireList(tbQuestionnaire);
        tbQuestionnaires.stream()
                .filter(q -> StringUtils.isNotBlank(q.getFormUrl()))
                .forEach(q -> q.setFormUrl(AstarConfig.getServerIp() + q.getFormUrl()));
        return tbQuestionnaires;
    }

    /**
     * 新增问卷调查管理
     * 
     * @param tbQuestionnaire 问卷调查管理
     * @return 结果
     */
    @Override
    public int insertTbQuestionnaire(TbQuestionnaire tbQuestionnaire)
    {
        tbQuestionnaire.setCreatedBy(SecurityUtils.getUsername());
        return tbQuestionnaireMapper.insertTbQuestionnaire(tbQuestionnaire);
    }

    /**
     * 修改问卷调查管理
     * 
     * @param tbQuestionnaire 问卷调查管理
     * @return 结果
     */
    @Override
    public int updateTbQuestionnaire(TbQuestionnaire tbQuestionnaire)
    {
        tbQuestionnaire.setUpdatedBy(SecurityUtils.getUsername());
        return tbQuestionnaireMapper.updateTbQuestionnaire(tbQuestionnaire);
    }

    /**
     * 批量删除问卷调查管理
     * 
     * @param ids 需要删除的问卷调查管理主键
     * @return 结果
     */
    @Override
    public int deleteTbQuestionnaireByIds(Long[] ids)
    {
        return tbQuestionnaireMapper.deleteTbQuestionnaireByIds(ids);
    }

    /**
     * 删除问卷调查管理信息
     * 
     * @param id 问卷调查管理主键
     * @return 结果
     */
    @Override
    public int deleteTbQuestionnaireById(Long id)
    {
        return tbQuestionnaireMapper.deleteTbQuestionnaireById(id);
    }

    @Override
    public int publish(TbQuestionnaire tbQuestionnaire) {
        tbQuestionnaire.setUpdatedBy(SecurityUtils.getUsername());
        tbQuestionnaire.setFormUrl(ShortUrlUtil.shortUrl(tbQuestionnaire.getId().toString()));
        return this.updateTbQuestionnaire(tbQuestionnaire);
    }

    /**
     * 获取问卷配置
     * @param url
     * @return {@link TbQuestionnaire}
     */
    @Override
    public TbQuestionnaire getQs(String url) {
        return tbQuestionnaireMapper.getQs(url);
    }


}
