package com.mesutpiskin.keycloak.auth.email;

import static com.mesutpiskin.keycloak.auth.email.ConditionalEmailAuthenticatorForm.OtpDecision.ABSTAIN;
import static com.mesutpiskin.keycloak.auth.email.ConditionalEmailAuthenticatorForm.OtpDecision.SHOW_OTP;
import static com.mesutpiskin.keycloak.auth.email.ConditionalEmailAuthenticatorForm.OtpDecision.SKIP_OTP;
import static org.keycloak.models.utils.KeycloakModelUtils.getRoleFromString;

import java.security.SecureRandom;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import io.opentelemetry.api.internal.StringUtils;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.http.HttpResponse;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;

import jakarta.ws.rs.core.MultivaluedMap;

public class ConditionalEmailAuthenticatorForm extends EmailAuthenticatorForm {

    public static final String SKIP = "skip";

    public static final String FORCE = "force";

    public static final String OTP_CONTROL_USER_ATTRIBUTE = "otpControlAttribute";

    public static final String SKIP_OTP_ROLE = "skipOtpRole";

    public static final String FORCE_OTP_ROLE = "forceOtpRole";

    public static final String SKIP_OTP_FOR_HTTP_HEADER = "noOtpRequiredForHeaderPattern";

    public static final String FORCE_OTP_FOR_HTTP_HEADER = "forceOtpForHeaderPattern";

    public static final String DEFAULT_OTP_OUTCOME = "defaultOtpOutcome";

    public static final String TRUSTED_DEVICE_ROLE = "trusted_device";

    public static final String TRUSTED_DEVICE_EXPIRATION_ATTRIBUTE = "trusted_device_expiry";

    public static final String TRUSTED_DEVICE_DAYS_ATTRIBUTE = "trusted_device_expiration_days";

    private static final String DEVICE_COOKIE_NAME = "trusted_device_id";

    private static final String TRUSTED_DEVICE_SET_ATTRIBUTE = "trusted_device_ids";

    private static final int DEFAULT_TRUSTED_DAYS = 30; // Dias por defecto


    enum OtpDecision {
        SKIP_OTP, SHOW_OTP, ABSTAIN
    }
	
	@Override
    public void authenticate(AuthenticationFlowContext context) {

        UserModel user = context.getUser();

        RealmModel realm = context.getRealm();

        Map<String, String> config = context.getAuthenticatorConfig().getConfig();

        String deviceId = getDeviceIdFromRequest(context);

        // Verificar si el usuario tiene el rol "trusted_device"
        if (userHasRole(realm, user, TRUSTED_DEVICE_ROLE)) {
            // Si el dispositivo sigue siendo confiable, omitir MFA
            if (isTrustedDeviceStillValid(user) && isTrustedDevice(user, deviceId)) {
                context.success();
                return;
            } else if(isTrustedDeviceStillValid(user)){
                showOtpForm(context);
                return;
            } else {
                // Si ha expirado, eliminar el rol y forzar MFA
                user.deleteRoleMapping(realm.getRole(TRUSTED_DEVICE_ROLE));
                user.removeAttribute(TRUSTED_DEVICE_EXPIRATION_ATTRIBUTE);
                user.removeAttribute(TRUSTED_DEVICE_SET_ATTRIBUTE);
            }
        }


        if (tryConcludeBasedOn(voteForUserOtpControlAttribute(user, config), context)) {
            return;
        }

        if (tryConcludeBasedOn(voteForUserRole(realm, user, config), context)) {
            return;
        }

        if (tryConcludeBasedOn(voteForHttpHeaderMatchesPattern(context.getHttpRequest().getHttpHeaders().getRequestHeaders(), config), context)) {
            return;
        }

        if (tryConcludeBasedOn(voteForDefaultFallback(config), context)) {
            return;
        }

        showOtpForm(context);
    }

    private String getDeviceIdFromRequest(AuthenticationFlowContext context) {
        Cookie cookie = context.getHttpRequest().getHttpHeaders().getCookies().get(DEVICE_COOKIE_NAME);
        return cookie != null ? cookie.getValue() : null;
    }

    private boolean isTrustedDevice(UserModel user, String deviceId) {
        if (deviceId == null || deviceId.isEmpty()) {
            return false;
        }

        Set<String> trustedDevices = user.getAttributeStream(TRUSTED_DEVICE_SET_ATTRIBUTE).collect(Collectors.toSet());
        return trustedDevices.contains(deviceId);
    }

    private boolean isTrustedDeviceStillValid(UserModel user) {
        String expiryDateAttr = user.getFirstAttribute(TRUSTED_DEVICE_EXPIRATION_ATTRIBUTE);
        if (expiryDateAttr == null || expiryDateAttr.isEmpty()) {
            return false;
        }

        try {
            long expiryTimestamp = Long.parseLong(expiryDateAttr);
            long currentTime = System.currentTimeMillis();
            return currentTime < expiryTimestamp;
        } catch (NumberFormatException e) {
            return false; // Si el valor no es un número válido, forzar MFA
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        RealmModel realm = context.getRealm();

        // Después de completar MFA, marcar el dispositivo como confiable
        if (!userHasRole(realm, user, TRUSTED_DEVICE_ROLE)) {
            RoleModel trustedRole = realm.getRole(TRUSTED_DEVICE_ROLE);
            if (trustedRole != null) {
                user.grantRole(trustedRole);
            }
        }
        // Obtener el ID del dispositivo desde la cookie
        String deviceId = getDeviceIdFromRequest(context);
        Set<String> trustedDevices = new HashSet<>(user.getAttributeStream(TRUSTED_DEVICE_SET_ATTRIBUTE).collect(Collectors.toSet()));

        // Si el deviceId ya existe, no se genera uno nuevo
        if (deviceId == null || deviceId.isEmpty() || !trustedDevices.contains(deviceId)) {
            deviceId = generateNewDeviceId(); // Solo se genera si no existe
            trustedDevices.add(deviceId);
            user.setAttribute(TRUSTED_DEVICE_SET_ATTRIBUTE, new ArrayList<>(trustedDevices));

            // Crear la cookie solo si no existe
            boolean isSecure = context.getSession().getContext().getUri().getBaseUri().getScheme().equals("https");
            NewCookie cookie = new NewCookie(
                    DEVICE_COOKIE_NAME, deviceId, "/", null, "Trusted Device",
                    getTrustedDeviceExpirationDays(user) * 24 * 60 * 60,
                    true,
                    isSecure
            );

            HttpResponse response = context.getSession().getContext().getHttpResponse();
            response.setCookieIfAbsent(cookie);
        }

        // Verificar si el usuario ya tiene una fecha de expiración
        String expiryAttr = user.getFirstAttribute(TRUSTED_DEVICE_EXPIRATION_ATTRIBUTE);

        if (StringUtils.isNullOrEmpty(expiryAttr)) {
            // Si no hay fecha de expiración, establecerla por primera vez
            int expirationDays = getTrustedDeviceExpirationDays(user);
            setTrustedDeviceExpiry(user, expirationDays);
        }

        context.success();
    }

    private String generateNewDeviceId() {
        byte[] randomBytes = new byte[16];
        new SecureRandom().nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    private int getTrustedDeviceExpirationDays(UserModel user) {
        String daysAttr = user.getFirstAttribute(TRUSTED_DEVICE_DAYS_ATTRIBUTE);

        if (StringUtils.isNullOrEmpty(daysAttr)) {
            user.setSingleAttribute(TRUSTED_DEVICE_DAYS_ATTRIBUTE, String.valueOf(DEFAULT_TRUSTED_DAYS));
            return DEFAULT_TRUSTED_DAYS;
        }

        return Integer.parseInt(daysAttr);
    }

    private void setTrustedDeviceExpiry(UserModel user, int expirationDays) {
        long expiryTimestamp = System.currentTimeMillis() + (expirationDays * 24 * 60 * 60 * 1000L);
        user.setSingleAttribute(TRUSTED_DEVICE_EXPIRATION_ATTRIBUTE, String.valueOf(expiryTimestamp));
    }

    private OtpDecision voteForDefaultFallback(Map<String, String> config) {

        if (!config.containsKey(DEFAULT_OTP_OUTCOME)) {
            return ABSTAIN;
        }

        switch (config.get(DEFAULT_OTP_OUTCOME)) {
            case SKIP:
                return SKIP_OTP;
            case FORCE:
                return SHOW_OTP;
            default:
                return ABSTAIN;
        }
    }

    private boolean tryConcludeBasedOn(OtpDecision state, AuthenticationFlowContext context) {

        switch (state) {

            case SHOW_OTP:
                showOtpForm(context);
                return true;

            case SKIP_OTP:
                context.success();
                return true;

            default:
                return false;
        }
    }

    private void showOtpForm(AuthenticationFlowContext context) {
        super.authenticate(context);
    }

    private OtpDecision voteForUserOtpControlAttribute(UserModel user, Map<String, String> config) {

        if (!config.containsKey(OTP_CONTROL_USER_ATTRIBUTE)) {
            return ABSTAIN;
        }

        String attributeName = config.get(OTP_CONTROL_USER_ATTRIBUTE);
        if (attributeName == null) {
            return ABSTAIN;
        }

        Optional<String> value = user.getAttributeStream(attributeName).findFirst();
        if (!value.isPresent()) {
            return ABSTAIN;
        }

        switch (value.get().trim()) {
            case SKIP:
                return SKIP_OTP;
            case FORCE:
                return SHOW_OTP;
            default:
                return ABSTAIN;
        }
    }

    private OtpDecision voteForHttpHeaderMatchesPattern(MultivaluedMap<String, String> requestHeaders, Map<String, String> config) {

        if (!config.containsKey(FORCE_OTP_FOR_HTTP_HEADER) && !config.containsKey(SKIP_OTP_FOR_HTTP_HEADER)) {
            return ABSTAIN;
        }

        //Inverted to allow white-lists, e.g. for specifying trusted remote hosts: X-Forwarded-Host: (1.2.3.4|1.2.3.5)
        if (containsMatchingRequestHeader(requestHeaders, config.get(SKIP_OTP_FOR_HTTP_HEADER))) {
            return SKIP_OTP;
        }

        if (containsMatchingRequestHeader(requestHeaders, config.get(FORCE_OTP_FOR_HTTP_HEADER))) {
            return SHOW_OTP;
        }

        return ABSTAIN;
    }

    private boolean containsMatchingRequestHeader(MultivaluedMap<String, String> requestHeaders, String headerPattern) {

        if (headerPattern == null) {
            return false;
        }

        //TODO cache RequestHeader Patterns
        //TODO how to deal with pattern syntax exceptions?
        // need CASE_INSENSITIVE flag so that we also have matches when the underlying container use a different case than what
        // is usually expected (e.g.: vertx)
        Pattern pattern = Pattern.compile(headerPattern, Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

        for (Map.Entry<String, List<String>> entry : requestHeaders.entrySet()) {

            String key = entry.getKey();

            for (String value : entry.getValue()) {

                String headerEntry = key.trim() + ": " + value.trim();

                if (pattern.matcher(headerEntry).matches()) {
                    return true;
                }
            }
        }

        return false;
    }

    private OtpDecision voteForUserRole(RealmModel realm, UserModel user, Map<String, String> config) {

        if (!config.containsKey(SKIP_OTP_ROLE) && !config.containsKey(FORCE_OTP_ROLE)) {
            return ABSTAIN;
        }

        if (userHasRole(realm, user, config.get(SKIP_OTP_ROLE))) {
            return SKIP_OTP;
        }

        if (userHasRole(realm, user, config.get(FORCE_OTP_ROLE))) {
            return SHOW_OTP;
        }

        return ABSTAIN;
    }

    private boolean userHasRole(RealmModel realm, UserModel user, String roleName) {

        if (roleName == null) {
            return false;
        }

        RoleModel role = getRoleFromString(realm, roleName);
        if (role != null) {
            return user.hasRole(role);
        }
        return false;
    }
}
