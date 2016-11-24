/*
 * Created on 18 nov 2016 ( Time 17:08:44 )
 * Generated by Telosys Tools Generator ( version 2.1.1 )
 */
package it.csi.sira.backend.metadata.integration.dao;

import it.csi.sira.backend.metadata.integration.dto.SipraMtdTStoricoFunzione;
import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;




/**
 * SipraMtdTStoricoFunzione DAO interface
 * 
 * @author Telosys Tools
 */
public interface SipraMtdTStoricoFunzioneDAO {

	//----------------------------------------------------------------------
	/**
	 * Finds a bean by its primary key 
	 * @param idStoricoFunzione
	 * @return the bean found or null if not found 
	 */
	public SipraMtdTStoricoFunzione findByPK(Integer idStoricoFunzione);

	public List<SipraMtdTStoricoFunzione> findAll();
	
	public List<SipraMtdTStoricoFunzione> findByCriteria(java.util.Map<String, Object> params);
	public List<SipraMtdTStoricoFunzione> findByCriteria(MapSqlParameterSource params);
	
	public <V> List<V> findByGenericCriteria(String query, RowMapper<V>  rowMapper, Map<String, Object> params);
	public <V> List<V> findByGenericCriteria(String query, RowMapper<V>  rowMapper, MapSqlParameterSource params);
	public List<SipraMtdTStoricoFunzione> findByGenericCriteria(String query, MapSqlParameterSource params);
	
	public void insert(SipraMtdTStoricoFunzione bean);

	public void update(SipraMtdTStoricoFunzione bean);
	
	public void update(String sql, Map<String, Object> param);

	public int deleteByPK(Integer idStoricoFunzione);
	
	public int delete(String query, Map<String, Object> params);
	public int delete(String query, MapSqlParameterSource params);

	public boolean exist(Map<String, Object> params);

    public RowMapper<SipraMtdTStoricoFunzione> getRowMapper();
}