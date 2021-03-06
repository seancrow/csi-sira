/*
 * Created on 25 nov 2016 ( Time 10:35:36 )
 * Generated by Telosys Tools Generator ( version 2.1.1 )
 */
package it.csi.sira.backend.metadata.integration.dao;

import it.csi.sira.backend.metadata.integration.dto.SipraMtdDStandardEspos;
import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;




/**
 * SipraMtdDStandardEspos DAO interface
 * 
 * @author Telosys Tools
 */
public interface SipraMtdDStandardEsposDAO {

	//----------------------------------------------------------------------
	/**
	 * Finds a bean by its primary key 
	 * @param idStandardEspos
	 * @return the bean found or null if not found 
	 */
	public SipraMtdDStandardEspos findByPK(Integer idStandardEspos);

	public List<SipraMtdDStandardEspos> findAll();
	
	public List<SipraMtdDStandardEspos> findByCriteria(java.util.Map<String, Object> params);
	public List<SipraMtdDStandardEspos> findByCriteria(MapSqlParameterSource params);
	
	public <V> List<V> findByGenericCriteria(String query, RowMapper<V>  rowMapper, Map<String, Object> params);
	public <V> List<V> findByGenericCriteria(String query, RowMapper<V>  rowMapper, MapSqlParameterSource params);
	public List<SipraMtdDStandardEspos> findByGenericCriteria(String query, MapSqlParameterSource params);
	
	public void insert(SipraMtdDStandardEspos bean);

	public void update(SipraMtdDStandardEspos bean);
	
	public void update(String sql, Map<String, Object> param);

	public int deleteByPK(Integer idStandardEspos);
	
	public int delete(String query, Map<String, Object> params);
	public int delete(String query, MapSqlParameterSource params);

	public boolean exist(Map<String, Object> params);

    public RowMapper<SipraMtdDStandardEspos> getRowMapper();
}
