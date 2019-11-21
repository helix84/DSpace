/**
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree and available online at
 *
 * http://www.dspace.org/license/
 */
package org.dspace.authenticate;

import java.sql.SQLException;
import java.util.Hashtable;
import java.util.HashSet;
import java.util.HashMap;
import java.util.Set;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.dspace.authorize.AuthorizeException;
import org.dspace.core.Context;
import org.dspace.core.LogManager;
import org.dspace.eperson.EPerson;
import org.dspace.eperson.Group;
import org.dspace.utils.DSpace;

/**
 * This combined LDAP authentication method supersedes both the 'LDAPAuthentication'
 * and the 'LDAPHierarchicalAuthentication' methods. It's capable of both:
 * - authenticaton  against a flat LDAP tree where all users are in the same unit
 *   (if search.user or search.password is not set)
 * - authentication against structured hierarchical LDAP trees of users. 
 *   An initial bind is required using a user name and password in order to
 *   search the tree and find the DN of the user. A second bind is then required to
 *   check the credentials of the user by binding directly to their DN.
 *
 * @author Stuart Lewis, Chris Yates, Alex Barbieri, Flavio Botelho, Reuben Pasquini, Samuel Ottenhoff, Ivan Masár
 * @version $Revision$
 */
public class LDAPAuthentication
    implements AuthenticationMethod {

    /** log4j category */
    private static Logger log = Logger.getLogger(LDAPAuthentication.class);

    /**
     * Let a real auth method return true if it wants.
     */
    public boolean canSelfRegister(Context context,
                                   HttpServletRequest request,
                                   String username)
        throws SQLException
    {
        // Looks to see if autoregister is set or not
        return new DSpace().getConfigurationService()
            .getPropertyAsType("authentication-ldap.autoregister", boolean.class);
    }

    /**
     *  Nothing here, initialization is done when auto-registering.
     */
    public void initEPerson(Context context, HttpServletRequest request,
            EPerson eperson)
        throws SQLException
    {
        // XXX should we try to initialize netid based on email addr,
        // XXX  for eperson created by some other method??
    }

    /**
     * Cannot change LDAP password through dspace, right?
     */
    public boolean allowSetPassword(Context context,
                                    HttpServletRequest request,
                                    String username)
        throws SQLException
    {
        return false;
    }

    /*
     * This is an explicit method.
     */
    public boolean isImplicit()
    {
        return false;
    }

    /*
     * Add all authenticated users to the group defined in dspace.cfg by
     * the login.specialgroup key.
     */
    public int[] getSpecialGroups(Context context, HttpServletRequest request)
    {
        // Prevents anonymous users from being added to this group, and the second check
        // ensures they are LDAP users
        try
        {
            if (!context.getCurrentUser().getNetid().equals(""))
            {
                String groupName = new DSpace().getConfigurationService()
                    .getProperty("authentication-ldap.login.specialgroup");
                if (StringUtils.isNotBlank(groupName))
                {
                    Group ldapGroup = Group.findByName(context, groupName);
                    if (ldapGroup == null)
                    {
                        // Oops - the group isn't there.
                        log.warn(LogManager.getHeader(context,
                                "ldap_specialgroup",
                                "Group defined in login.specialgroup does not exist"));
                        return new int[0];
                    } else
                    {
                        return new int[] { ldapGroup.getID() };
                    }
                }
            }
        }
        catch (Exception npe) {
            // The user is not an LDAP user, so we don't need to worry about them
        }
        return new int[0];
    }

    /*
     * Authenticate the given credentials.
     * This is the heart of the authentication method: test the
     * credentials for authenticity, and if accepted, attempt to match
     * (or optionally, create) an <code>EPerson</code>.  If an <code>EPerson</code> is found it is
     * set in the <code>Context</code> that was passed.
     *
     * @param context
     *  DSpace context, will be modified (ePerson set) upon success.
     *
     * @param username
     *  Username (or email address) when method is explicit. Use null for
     *  implicit method.
     *
     * @param password
     *  Password for explicit auth, or null for implicit method.
     *
     * @param realm
     *  Realm is an extra parameter used by some authentication methods, leave null if
     *  not applicable.
     *
     * @param request
     *  The HTTP request that started this operation, or null if not applicable.
     *
     * @return One of:
     *   SUCCESS, BAD_CREDENTIALS, CERT_REQUIRED, NO_SUCH_USER, BAD_ARGS
     * <p>Meaning:
     * <br>SUCCESS         - authenticated OK.
     * <br>BAD_CREDENTIALS - user exists, but credentials (e.g. passwd) don't match
     * <br>CERT_REQUIRED   - not allowed to login this way without X.509 cert.
     * <br>NO_SUCH_USER    - user not found using this method.
     * <br>BAD_ARGS        - user/pw not appropriate for this method
     */
    public int authenticate(Context context,
                            String netid,
                            String password,
                            String realm,
                            HttpServletRequest request)
        throws SQLException
    {
        log.info(LogManager.getHeader(context, "auth", "attempting trivial auth of user="+netid));

        // Skip out when no netid or password is given.
        if (netid == null || password == null)
        {
            return BAD_ARGS;
        }

        // Locate the eperson
        EPerson eperson = null;
        try
        {
                eperson = EPerson.findByNetid(context, netid.toLowerCase());
        }
        catch (SQLException e)
        {
        }
        SpeakerToLDAP ldap = new SpeakerToLDAP(log);

        // Get the DN of the user
        boolean anonymousSearch = new DSpace().getConfigurationService()
            .getPropertyAsType("authentication-ldap.search.anonymous", boolean.class);
        String adminUser = new DSpace().getConfigurationService().getProperty("authentication-ldap.search.user");
        String adminPassword = new DSpace().getConfigurationService().getProperty("authentication-ldap.search.password");
        String objectContext = new DSpace().getConfigurationService().getProperty("authentication-ldap.object_context");
        String idField = new DSpace().getConfigurationService().getProperty("authentication-ldap.id_field");
        String dn = "";

        // If adminUser is blank and anonymous search is not allowed, then we can't search so
        // construct the DN instead of searching it
System.out.println("search? " + StringUtils.isBlank(adminUser) + StringUtils.isBlank(adminPassword) + !anonymousSearch);
        if ((StringUtils.isBlank(adminUser) || StringUtils.isBlank(adminPassword)) && !anonymousSearch)
        {
            dn = idField + "=" + netid + "," + objectContext;
System.out.println(" dn constructed:" + dn);
        }
        else
        {
            dn = ldap.getDNOfUser(adminUser, adminPassword, context, netid);
System.out.println(" after getDNOfUser():" + ldap.ldapGroupSet);
        }

        // Check a DN was found
        if (StringUtils.isBlank(dn))
        {
            log.info(LogManager
                .getHeader(context, "failed_login", "no DN found for user " + netid));
            return BAD_CREDENTIALS;
        }

        // if they entered a netid that matches an eperson
        if (eperson != null)
        {
            // e-mail address corresponds to active account
            if (eperson.getRequireCertificate())
            {
                return CERT_REQUIRED;
            }
            else if (!eperson.canLogIn())
            {
                return BAD_ARGS;
            }

            if (ldap.ldapAuthenticate(dn, password, context))
            {
                context.setCurrentUser(eperson);

                // assign user to groups based on ldap dn
System.out.println("1 assignGroups(" + dn + ", " + ldap.ldapGroupSet + ", " + context + ");");
                assignGroups(dn, ldap.ldapGroupSet, context);
                
                log.info(LogManager
                    .getHeader(context, "authenticate", "type=ldap"));
                return SUCCESS;
            }
            else
            {
                return BAD_CREDENTIALS;
            }
        }
        else
        {
            // the user does not already exist so try and authenticate them
            // with ldap and create an eperson for them

            if (ldap.ldapAuthenticate(dn, password, context))
            {
                // Register the new user automatically
                log.info(LogManager.getHeader(context,
                                "autoregister", "netid=" + netid));

                String email = ldap.ldapEmail;

                // Check if we were able to determine an email address from LDAP
                if (StringUtils.isEmpty(email))
                {
                    // If no email, check if we have a "netid_email_domain". If so, append it to the netid to create email
                    final String netid_email_domain = new DSpace().getConfigurationService()
                        .getProperty("authentication-ldap.netid_email_domain");
                    if (StringUtils.isNotEmpty(netid_email_domain))
                    {
                        email = netid + netid_email_domain;
                    }
                    else
                    {
                        // We don't have a valid email address. We'll default it to 'netid' but log a warning
                        log.warn(LogManager.getHeader(context, "autoregister",
                                "Unable to locate email address for account '" + netid + "', so it has been set to '" +
                                netid + "'. " +
                                "Please check the LDAP 'email_field' OR consider configuring 'netid_email_domain'."));
                        email = netid;
                    }
                }

                if (StringUtils.isNotEmpty(email))
                {
                    try
                    {
                        eperson = EPerson.findByEmail(context, email);
                        if (eperson!=null)
                        {
                            log.info(LogManager.getHeader(context,
                                    "type=ldap-login", "type=ldap_but_already_email"));
                            context.turnOffAuthorisationSystem();
                            eperson.setNetid(netid.toLowerCase());
                            eperson.update();
                            context.commit();
                            context.restoreAuthSystemState();
                            context.setCurrentUser(eperson);

                            // assign user to groups based on ldap dn
System.out.println("2 assignGroups(" + dn + ", " + ldap.ldapGroupSet + ", " + context + ");");
                            assignGroups(dn, ldap.ldapGroupSet, context);

                            return SUCCESS;
                        }
                        else
                        {
                            if (canSelfRegister(context, request, netid))
                            {
                                // TEMPORARILY turn off authorisation
                                try
                                {
                                    context.turnOffAuthorisationSystem();
                                    eperson = EPerson.create(context);
                                    if (StringUtils.isNotEmpty(email))
                                    {
                                        eperson.setEmail(email);
                                    }
                                    if (StringUtils.isNotEmpty(ldap.ldapGivenName))
                                    {
                                        eperson.setFirstName(ldap.ldapGivenName);
                                    }
                                    if (StringUtils.isNotEmpty(ldap.ldapSurname))
                                    {
                                        eperson.setLastName(ldap.ldapSurname);
                                    }
                                    if (StringUtils.isNotEmpty(ldap.ldapPhone))                                    
                                    {
                                        eperson.setMetadata("phone", ldap.ldapPhone);
                                    }
                                    eperson.setNetid(netid.toLowerCase());
                                    eperson.setCanLogIn(true);
                                    AuthenticationManager.initEPerson(context, request, eperson);
                                    eperson.update();
                                    context.commit();
                                    context.setCurrentUser(eperson);

                                    // assign user to groups based on ldap dn
System.out.println("3 assignGroups(" + dn + ", " + ldap.ldapGroupSet + ", " + context + ");");
                                    assignGroups(dn, ldap.ldapGroupSet, context);
                                }
                                catch (AuthorizeException e)
                                {
                                    return NO_SUCH_USER;
                                }
                                finally
                                {
                                    context.restoreAuthSystemState();
                                }

                                log.info(LogManager.getHeader(context, "authenticate",
                                            "type=ldap-login, created ePerson"));
                                return SUCCESS;
                            }
                            else
                            {
                                // No auto-registration for valid certs
                                log.info(LogManager.getHeader(context,
                                                "failed_login", "type=ldap_but_no_record"));
                                return NO_SUCH_USER;
                            }
                        }
                    }
                    catch (AuthorizeException e)
                    {
                        eperson = null;
                    }
                    finally
                    {
                        context.restoreAuthSystemState();
                    }
                }
            }
        }
        return BAD_ARGS;
    }

    /**
     * Internal class to manage LDAP query and results, mainly
     * because there are multiple values to return.
     */
    private static class SpeakerToLDAP {

        private Logger log = null;

        protected String ldapEmail = null;
        protected String ldapGivenName = null;
        protected String ldapSurname = null;
        protected String ldapPhone = null;
        protected Set<String> ldapGroupSet = new HashSet<String>();


        /** LDAP settings */
        String ldap_provider_url = new DSpace().getConfigurationService().getProperty("authentication-ldap.provider_url");
        String ldap_id_field = new DSpace().getConfigurationService().getProperty("authentication-ldap.id_field");
        String ldap_search_context = new DSpace().getConfigurationService().getProperty("authentication-ldap.search_context");
        String ldap_search_scope = new DSpace().getConfigurationService().getProperty("authentication-ldap.search_scope");

        String ldap_email_field = new DSpace().getConfigurationService().getProperty("authentication-ldap.email_field");
        String ldap_givenname_field = new DSpace().getConfigurationService().getProperty("authentication-ldap.givenname_field");
        String ldap_surname_field = new DSpace().getConfigurationService().getProperty("authentication-ldap.surname_field");
        String ldap_phone_field = new DSpace().getConfigurationService().getProperty("authentication-ldap.phone_field");
        String ldap_group_field = new DSpace().getConfigurationService().getProperty("authentication-ldap.login.groupmap.attribute"); 

        SpeakerToLDAP(Logger thelog)
        {
            log = thelog;
        }

        protected String getDNOfUser(String adminUser, String adminPassword, Context context, String netid)
        {
            // The resultant DN
            String resultDN;

            // The search scope to use (default to 0)
            int ldap_search_scope_value = 0;
            try
            {
                ldap_search_scope_value = Integer.parseInt(ldap_search_scope.trim());
            }
            catch (NumberFormatException e)
            {
                // Log the error if it has been set but is invalid
                if (ldap_search_scope != null)
                {
                    log.warn(LogManager.getHeader(context,
                            "ldap_authentication", "invalid search scope: " + ldap_search_scope));
                }
            }

            // Set up environment for creating initial context
            Hashtable env = new Hashtable(11);
            env.put(javax.naming.Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(javax.naming.Context.PROVIDER_URL, ldap_provider_url);

            if (StringUtils.isNotBlank(adminUser) && StringUtils.isNotBlank(adminPassword))
            {
                // Use admin credentials for search// Authenticate
                env.put(javax.naming.Context.SECURITY_AUTHENTICATION, "simple");
                env.put(javax.naming.Context.SECURITY_PRINCIPAL, adminUser);
                env.put(javax.naming.Context.SECURITY_CREDENTIALS, adminPassword);
            }
            else
            {
                // Use anonymous authentication
                env.put(javax.naming.Context.SECURITY_AUTHENTICATION, "none");
            }

            DirContext ctx = null;
            try
            {
                // Create initial context
                ctx = new InitialDirContext(env);

                Attributes matchAttrs = new BasicAttributes(true);
                matchAttrs.put(new BasicAttribute(ldap_id_field, netid));

                // look up attributes
                try
                {
                    SearchControls ctrls = new SearchControls();
                    ctrls.setSearchScope(ldap_search_scope_value);

                    NamingEnumeration<SearchResult> answer = ctx.search(
                            ldap_provider_url + ldap_search_context,
                            "(&({0}={1}))", new Object[] { ldap_id_field,
                                    netid }, ctrls);

                    while (answer.hasMoreElements()) {
                        SearchResult sr = answer.next();
                        if (StringUtils.isEmpty(ldap_search_context)) {
                            resultDN = sr.getName();
                        } else {
                            resultDN = (sr.getName() + "," + ldap_search_context);
                        }

                        String attlist[] = {ldap_email_field, ldap_givenname_field,
                                            ldap_surname_field, ldap_phone_field, ldap_group_field};
                        Attributes atts = sr.getAttributes();
                        Attribute att;

                        if (attlist[0] != null) {
                            att = atts.get(attlist[0]);
                            if (att != null)
                            {
                                ldapEmail = (String) att.get();
                            }
                        }

                        if (attlist[1] != null) {
                            att = atts.get(attlist[1]);
                            if (att != null)
                            {
                                ldapGivenName = (String) att.get();
                            }
                        }

                        if (attlist[2] != null) {
                            att = atts.get(attlist[2]);
                            if (att != null)
                            {
                                ldapSurname = (String) att.get();
                            }
                        }
System.out.println("  ldapSurname:" + ldapSurname);

                        if (attlist[3] != null) {
                            att = atts.get(attlist[3]);
                            if (att != null)
                            {
                                ldapPhone = (String) att.get();
                            }
                        }
                
System.out.println("  attlist[4] = '" + attlist[4] + "'");
                        if (attlist[4] != null) {
                            try {
                                // loop all attributes
                                for (NamingEnumeration attr = atts.getAll(); attr.hasMore();)
                                {
                                    Attribute attribute = (Attribute) attr.next();
                                    // is this the group attribute?
                                    if (attribute.getID().equalsIgnoreCase(attlist[4]))
                                    {
                                        // loop all values of the group attribute, add them to a set
System.out.println("  attr MATCH: '" + attribute.getID() + "'");
                                        for (NamingEnumeration val = attribute.getAll(); val.hasMore();)
                                        {
                                            String lcLdapGroup = ((String) val.next()).toLowerCase();
System.out.println("  attr MATCH loop; lcLdapGroup: " + lcLdapGroup);
                                            ldapGroupSet.add(lcLdapGroup);
System.out.println("  Group added to ldapGroupSet as\t" + lcLdapGroup);
                                        }
                                    }
                                }
                            } catch (NamingException e) {
                                log.debug(LogManager.getHeader(context, "error getting groups from LDAP for ", resultDN));
                            }
                        }

                        if (answer.hasMoreElements()) {
                            // Oh dear - more than one match
                            // Ambiguous user, can't continue

                        } else {
                            log.debug(LogManager.getHeader(context, "got DN", resultDN));
                            return resultDN;
                        }
                    }
                }
                catch (NamingException e)
                {
                    // if the lookup fails go ahead and create a new record for them because the authentication
                    // succeeded
                    log.warn(LogManager.getHeader(context,
                                "ldap_attribute_lookup", "type=failed_search "
                                        + e));
                }
            }
            catch (NamingException e)
            {
                log.warn(LogManager.getHeader(context,
                            "ldap_authentication", "type=failed_auth " + e));
            }
            finally
            {
                // Close the context when we're done
                try
                {
                    if (ctx != null)
                    {
                        ctx.close();
                    }
                }
                catch (NamingException e)
                {
                }
            }

            // No DN match found
            return null;
        }

        /**
         * contact the ldap server and attempt to authenticate
         */
        protected boolean ldapAuthenticate(String netid, String password,
                        Context context) {
            if (!password.equals("")) {
                // Set up environment for creating initial context
                Hashtable<String, String> env = new Hashtable<String, String>();
                env.put(javax.naming.Context.INITIAL_CONTEXT_FACTORY,
                        "com.sun.jndi.ldap.LdapCtxFactory");
                env.put(javax.naming.Context.PROVIDER_URL, ldap_provider_url);

                // Authenticate
                env.put(javax.naming.Context.SECURITY_AUTHENTICATION, "Simple");
                env.put(javax.naming.Context.SECURITY_PRINCIPAL, netid);
                env.put(javax.naming.Context.SECURITY_CREDENTIALS, password);
                env.put(javax.naming.Context.AUTHORITATIVE, "true");
                env.put(javax.naming.Context.REFERRAL, "follow");

                DirContext ctx = null;
                try {
                    // Try to bind
                    ctx = new InitialDirContext(env);
                } catch (NamingException e) {
                    log.warn(LogManager.getHeader(context,
                            "ldap_authentication", "type=failed_auth " + e));
                    return false;
                } finally {
                    // Close the context when we're done
                    try {
                        if (ctx != null)
                        {
                            ctx.close();
                        }
                    } catch (NamingException e) {
                    }
                }
            } else {
                return false;
            }

            return true;
        }        
    }

    /*
     * Returns URL to which to redirect to obtain credentials (either password
     * prompt or e.g. HTTPS port for client cert.); null means no redirect.
     *
     * @param context
     *  DSpace context, will be modified (ePerson set) upon success.
     *
     * @param request
     *  The HTTP request that started this operation, or null if not applicable.
     *
     * @param response
     *  The HTTP response from the servlet method.
     *
     * @return fully-qualified URL
     */
    public String loginPageURL(Context context,
                            HttpServletRequest request,
                            HttpServletResponse response)
    {
        return response.encodeRedirectURL(request.getContextPath() +
                                          "/ldap-login");
    }

    /**
     * Returns message key for title of the "login" page, to use
     * in a menu showing the choice of multiple login methods.
     *
     * @param context
     *  DSpace context, will be modified (ePerson set) upon success.
     *
     * @return Message key to look up in i18n message catalog.
     */
    public String loginPageTitle(Context context)
    {
        return "org.dspace.eperson.LDAPAuthentication.title";
    }


    /*
     * Add the authenticated user to all groups defined in dspace.cfg by
     * the authentication-ldap.login.groupmap.* key (group map).
     *
     * Assign the user identified by dn to all groups in ldapGroupSet
     * that are also mapped to DSpace groups by the group map.
     * If ldapGroupSet is an empty set, assign the user to groups 
     * from the group map that are a substring of dn.
     */
    private void assignGroups(String dn, Set<String> ldapGroupSet, Context context)
    {
        if (StringUtils.isBlank(dn)) 
        {
            return;
        }

        System.out.println("dn:" + dn);

        HashMap<String, String> groupMap = new HashMap<String, String>(); // <LDAP group attribute value, DSpace group name>

        // read groupMap from DSpace configuration
        // TODO: ConfigurationService.getArrayProperty() from DSpace 6;
        //       should be simpler but incompatible with DSpace 5
        int i = 1;
        String groupMapItem = new DSpace().getConfigurationService().getProperty("authentication-ldap.login.groupmap." + i);

        while (groupMapItem != null)
        {
            String t[] = groupMapItem.split(":");
System.out.println("  groupMapItem: " + groupMapItem);
            groupMap.put(t[0].toLowerCase(), t[1]);
 
            groupMapItem = new DSpace().getConfigurationService().getProperty("authentication-ldap.login.groupmap." + ++i);
        }

        // take the set of map keys (mapped LDAP groups) and find
        // an intersection with user's ldapGroupSet
        Set<String> groupMapGroupSet = groupMap.keySet();
for (String g : groupMapGroupSet) System.out.println("  groupMapGroupSet: " + g);

        if (ldapGroupSet.isEmpty())
        {
System.out.println("  ldapGroupSet is empty");
            // assign groups by matching DN substring
            for (String groupMapGroup : groupMapGroupSet) {
                if (StringUtils.containsIgnoreCase(dn, groupMapGroup + ",")) {
                    String dspaceGroup = groupMap.get(groupMapGroup);
                    assignGroup(context, dspaceGroup);
System.out.println("  assigned group: " + dspaceGroup);
                }
            }
        } else {
            // assign groups by LDAP group

            Set<String> intersection = new HashSet<String>(ldapGroupSet);
for (String g : ldapGroupSet) System.out.println("  ldapGroupSet: " + g);
            intersection.retainAll(groupMapGroupSet);
for (String g : intersection) System.out.println("  intersection: " + g);
    
            // assign the current user to DSpace groups for which both is true:
            // * user is a member of the LDAP group
            // * the groups have a configured mapping (LDAP to DSpace groups)
            for (String ldapGroup : intersection) {
                String dspaceGroup = groupMap.get(ldapGroup);
                assignGroup(context, dspaceGroup);
System.out.println("  assigned group: " + dspaceGroup);
            }
        }
    }


    /*
     * Add the authenticated user to the specified DSpace group
     */
    private void assignGroup(Context context, String dspaceGroupName)
    {
        try
        {
            Group ldapGroup = Group.findByName(context, dspaceGroupName);
            if (ldapGroup != null)
            {
                ldapGroup.addMember(context.getCurrentUser());
                ldapGroup.update();
                context.commit();
            }
            else
            {
                // The group does not exist
                log.warn(LogManager.getHeader(context,
                        "ldap_assignGroupsBasedOnLdapDn",
                        "Group defined in authentication-ldap.login.groupmap.* does not exist :: " + dspaceGroupName));
            }
        }
        catch (AuthorizeException ae)
        {
            log.debug(LogManager.getHeader(context, "assignGroupsBasedOnLdapDn could not authorize addition to group", dspaceGroupName));
        }
        catch (SQLException e)
        {
            log.debug(LogManager.getHeader(context, "assignGroupsBasedOnLdapDn could not find group", dspaceGroupName));
        }
    }
}
