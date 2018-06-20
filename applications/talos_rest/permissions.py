from rest_framework import permissions

class IsBasicAuthenticated(permissions.BasePermission):
    message = 'you do not have a permission'

    def has_permission(self, request, view):
        if request.method not in list(view.allowed_methods):
            return True

        authentication_evidences = ('authenticated',
                                   'knowledge_factor',
                                   'knowledge_factor_password',
                                   )

        provided_evidence = request.principal._evidences_effective

        result = []
        for evidence in authentication_evidences:
            if evidence not in provided_evidence:
                result.append(evidence)
        if len(result) > 0:
            self.message = result
            return False
        return True


class IsAuthenticated(permissions.BasePermission):
    message = 'you do not have a permission'

    def has_permission(self, request, view):
        # For not allowed method we should raise 405, because of it we pass this this
        # permission checker

        if request.method not in list(view.allowed_methods):
            return True

        authentication_evidences = ('authenticated',
                                    'knowledge_factor',
                                    'knowledge_factor_password',
                                    'ownership_factor',
                                    'ownership_factor_otp_token',
                                    )

        provided_evidences = request.principal._evidences_effective

        result = []
        for evidence in authentication_evidences:
            if evidence not in provided_evidences:
                result.append(evidence)

        if len(result) > 0:
            if str(request.principal) != 'Anonymous':
                is_secure = request.principal.profile.is_secure
                if is_secure:
                    result.append("ownership_factor_google_authenticator")
                else:
                    result.append("ownership_factor_phone")

            self.message = result

            return False
        return True

