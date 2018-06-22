package com.test.web.config;

import org.apache.log4j.Logger;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Iterator;
/**
 * 此类是决策器： 用来对 用户应有的角色,与URL地址可以访问的角色进行对比,如果不匹配则抛出异常
 */

public class CustomAccessDecisionManager implements AccessDecisionManager {
    private static final Logger logger = Logger.getLogger(CustomAccessDecisionManager.class);
    /**
     * 决策方法： 如果方法执行完毕没有抛出异常,则说明可以放行, 否则抛出异常 AccessDeniedException
     */
    @Override
    public void decide(Authentication authentication, Object object,Collection<ConfigAttribute> configAttributes) throws AccessDeniedException, InsufficientAuthenticationException {
        if (configAttributes == null) {
            return;
        }
        //config urlroles
        Iterator<ConfigAttribute> iterator = configAttributes.iterator();
        // 如果登陆成功,则信息会存储在Authorities中
       // 前台传入的url的角色，UrlDaoImpl.getAttributes获得的
        while (iterator.hasNext()) {
            ConfigAttribute configAttribute = iterator.next();
            //need role
            String needRole = configAttribute.getAttribute();
            //user roles
            for (GrantedAuthority ga : authentication.getAuthorities()) {
                if (needRole.equals(ga.getAuthority())) {
                    return;
                }
            }
            logger.info("need role is " + needRole);
        }
        throw new AccessDeniedException("Cannot Access!");
    }

    @Override
    public boolean supports(ConfigAttribute configAttribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }

}
