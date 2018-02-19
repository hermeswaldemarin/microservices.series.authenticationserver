package com.hermeswaldemarin.microservices.authenticationserver.config;

import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.util.Assert;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

public class CustomJdbcUserDetailsManager extends JdbcUserDetailsManager {

    private String externalIdByUsername = "select externalid from users where username = ?";
    private static final String createUserSql = "insert into users (username, password,externalid, enabled) values (?,?,?,?)";
    private static final String createAuthoritySql = "insert into authorities (username, authority) values (?,?)";
    private static final String createEmailTokenSql = "insert into mailtoken (username, token) values (?,?)";
    private static final String getUserNameByEmailToken = "select username from mailtoken where token = ?";

    public UserDetails loadUserByUsername(String username){
        UserDetails user = super.loadUserByUsername(username);
        String externalid = null;
        List<String> external = loadExternalId(username);
        if(external.get(0) != null && !external.get(0).equals("")){
            externalid = external.get(0);
        }

        return new CustomUserDetails(user, externalid);
    }

    protected List<String> loadExternalId(String username) {
        return this.getJdbcTemplate().query(this.externalIdByUsername, new String[]{username}, new RowMapper<String>() {
            public String mapRow(ResultSet rs, int rowNum) throws SQLException {
                return rs.getString(1);
            }
        });
    }

    public void createUser(final CustomUserDetails user) {
        validateUserDetailsCustom(user);
        getJdbcTemplate().update(createUserSql, new PreparedStatementSetter() {
            public void setValues(PreparedStatement ps) throws SQLException {
                ps.setString(1, user.getUsername());
                ps.setString(2, user.getPassword());
                ps.setString(3, user.getExternalid());
                ps.setBoolean(4, user.isEnabled());
            }

        });

        if (getEnableAuthorities()) {
            insertUserAuthoritiesCustom(user);
        }
    }

    private void validateUserDetailsCustom(UserDetails user) {
        Assert.hasText(user.getUsername(), "Username may not be empty or null");
        validateAuthoritiesCustom(user.getAuthorities());
    }

    private void validateAuthoritiesCustom(Collection<? extends GrantedAuthority> authorities) {
        Assert.notNull(authorities, "Authorities list must not be null");

        for (GrantedAuthority authority : authorities) {
            Assert.notNull(authority, "Authorities list contains a null entry");
            Assert.hasText(authority.getAuthority(),
                    "getAuthority() method must return a non-empty string");
        }
    }

    private void insertUserAuthoritiesCustom(UserDetails user) {
        for (GrantedAuthority auth : user.getAuthorities()) {
            getJdbcTemplate().update(createAuthoritySql, user.getUsername(),
                    auth.getAuthority());
        }
    }

    public String getUserNameByToken(String emailToken) {
        List<String> data = this.getJdbcTemplate().query(getUserNameByEmailToken, new String[]{emailToken}, new RowMapper<String>() {
            public String mapRow(ResultSet rs, int rowNum) throws SQLException {
                return rs.getString(1);
            }
        });
        Assert.notEmpty(data,
                "Invalid Token");
        return data.get(0);
    }

    public String createMailToken(UserDetails user) {
        String token = UUID.randomUUID().toString();
        getJdbcTemplate().update(createEmailTokenSql, user.getUsername(),
                token);
        return token;
    }

}
