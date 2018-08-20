package org.wso2.carbon.identity.conditional.auth.functions.user;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.core.util.AnonymousSessionUtil;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.conditional.auth.functions.user.internal.UserFunctionsServiceHolder;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;

public class UpdateUserRolesFunctionImpl implements UpdateUserRolesFunction {

    private static final Log LOG = LogFactory.getLog(UpdateUserRolesFunctionImpl.class);

    @Override
    public void updateUserRoles(JsAuthenticatedUser user, List<String> newRoles, List<String> deletingRoles) {

        if (user != null && newRoles != null && deletingRoles != null) {
            try {
                String tenantDomain = user.getWrapped().getTenantDomain();
                String userStoreDomain = user.getWrapped().getUserStoreDomain();
                String username = user.getWrapped().getUserName();
                UserRealm userRealm = getUserRealm(tenantDomain);
                if (userRealm != null) {
                    UserStoreManager userStore = getUserStoreManager(tenantDomain, userRealm, userStoreDomain);
                    if (userStore != null) {
                        /*
                        Get all user roles. Then filter both new roles and deleting roles against existing user roles.
                        */
                        List<String> roleListOfUser = Arrays.asList(userStore.getRoleListOfUser(username));
                        List<String> filteredNewRoles = newRoles.stream()
                                .filter(role -> !roleListOfUser.contains(role))
                                .distinct()
                                .collect(Collectors.toList());
                        /*
                        Since catching user store exception within stream operations is not possible, filter invalid
                        roles separately
                         */
                        List<String> nonExistingRoles = new ArrayList<>();
                        for (String eachRole : filteredNewRoles) {
                            if (!userStore.isExistingRole(eachRole)) {
                                nonExistingRoles.add(eachRole);
                            }
                        }
                        filteredNewRoles.removeAll(nonExistingRoles);
                        userStore.updateRoleListOfUser(
                                username,
                                deletingRoles.stream()
                                        .filter(roleListOfUser::contains)
                                        .distinct().toArray(String[]::new),
                                filteredNewRoles.toArray(new String[0])
                        );
                    }
                }
            } catch (UserStoreException e) {
                LOG.error("Error in getting user from store at the function ", e);
            } catch (FrameworkException e) {
                LOG.error("Error in evaluating the function ", e);
            }
        } else {
            LOG.error("This function require three parameters but invalid parameters are detected. " +
                    "Please use an empty array if any of the add or delete user role sets are not required");
        }
    }

    private UserRealm getUserRealm(String tenantDomain) throws FrameworkException {

        UserRealm realm;
        try {
            realm = AnonymousSessionUtil.getRealmByTenantDomain(UserFunctionsServiceHolder.getInstance()
                    .getRegistryService(), UserFunctionsServiceHolder.getInstance().getRealmService(), tenantDomain);
        } catch (CarbonException e) {
            throw new FrameworkException(
                    "Error occurred while retrieving the Realm for " + tenantDomain + " to retrieve user roles", e);
        }
        return realm;
    }

    private UserStoreManager getUserStoreManager(String tenantDomain, UserRealm realm, String userDomain)
            throws FrameworkException {

        UserStoreManager userStore;
        try {
            if (StringUtils.isNotBlank(userDomain)) {
                userStore = realm.getUserStoreManager().getSecondaryUserStoreManager(userDomain);
            } else {
                userStore = realm.getUserStoreManager();
            }

            if (userStore == null) {
                throw new FrameworkException(
                        String.format("Invalid user store domain (given : %s) or tenant domain (given: %s).",
                                userDomain, tenantDomain));
            }
        } catch (UserStoreException e) {
            throw new FrameworkException(
                    "Error occurred while retrieving the UserStoreManager from Realm for " + tenantDomain
                            + " to retrieve user roles", e);
        }
        return userStore;
    }
}
