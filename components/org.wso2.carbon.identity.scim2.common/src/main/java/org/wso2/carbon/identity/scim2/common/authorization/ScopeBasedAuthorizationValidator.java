package org.wso2.carbon.identity.scim2.common.authorization;

import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil;
import org.wso2.charon3.core.exceptions.BadRequestException;
import org.wso2.charon3.core.exceptions.ForbiddenException;


public class ScopeBasedAuthorizationValidator implements AuthorizationValidator {


    @java.lang.Override
    public void validateScope(String operation) throws ForbiddenException, BadRequestException {

        String scope = AuthConfigurationUtil.getInstance().getScopeForOperation(operation);

        if (scope == null) {
            throw new BadRequestException("Invalid operation: " + operation);
        }

        List<Strings> authorizedScopes = PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getAuthorizedScopes();

        if (authorizedScopes != null || !authorizedScopes.contains(scope)) {
            throw new ForbiddenException("User does not have the required scope: " + scope);
        }
    }
}
