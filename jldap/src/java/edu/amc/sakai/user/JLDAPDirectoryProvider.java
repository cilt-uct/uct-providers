/**********************************************************************************
 * $URL$
 * $Id$
 ***********************************************************************************
 *
 * Copyright (c) 2003, 2004, 2005 The Regents of the University of Michigan, Trustees of Indiana University,
 *                  Board of Trustees of the Leland Stanford, Jr., University, and The MIT Corporation
 * 
 * Licensed under the Educational Community License Version 1.0 (the "License");
 * By obtaining, using and/or copying this Original Work, you agree that you have read,
 * understand, and will comply with the terms and conditions of the Educational Community License.
 * You may obtain a copy of the License at:
 * 
 *      http://cvs.sakaiproject.org/licenses/license_1_0.html
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE
 * AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 **********************************************************************************/

/**
 * <p>
 * An implementation of a Sakai UserDirectoryProvider that authenticates/retrieves 
 * users from an LDAP directory.
 * </p>
 * 
 * @author David Ross, Albany Medical College
 * @author Rishi Pande, Virginia Tech
 * @version $Revision$
 */

package edu.amc.sakai.user;

import java.security.MessageDigest;
import java.util.Collection;
import java.util.Hashtable;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.List;

import org.sakaiproject.user.api.User;
import org.sakaiproject.user.api.UserDirectoryProvider;
import org.sakaiproject.user.api.UserEdit;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.LDAPSocketFactory;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPAttribute;

import org.sakaiproject.user.api.User;
import org.sakaiproject.db.api.SqlService;
import org.sakaiproject.user.api.DisplayAdvisorUDP;
import org.sakaiproject.tool.api.Placement;
//import org.sakaiproject.tool.api.Session;
//import org.sakaiproject.tool.cover.SessionManager;
import org.sakaiproject.tool.cover.ToolManager;
import org.sakaiproject.site.api.SiteService;
import org.sakaiproject.site.api.Site;
import org.sakaiproject.component.api.ServerConfigurationService; 
import org.sakaiproject.useralias.logic.UserAliasLogic;
import org.sakaiproject.useralias.model.UserAliasItem;


import sun.misc.BASE64Encoder;


//following imports are only needed if you are doing group membership -> sakai type matching (see section in getUser())
/*******
import com.novell.ldap.LDAPAttribute;

import com.novell.ldap.util.DN;

import com.novell.ldap.util.RDN;

import java.util.Vector;

import java.util.ListIterator;
 *******/

public class JLDAPDirectoryProvider implements UserDirectoryProvider, DisplayAdvisorUDP {
	private String ldapHost = ""; //address of ldap server
	private int ldapPort = 389; //port to connect to ldap server on
	private String keystoreLocation = ""; // keystore location (only needed for SSL connections)
	private String keystorePassword = ""; // keystore password (only needed for SSL connections)
	private String basePath = ""; //base path to start lookups on
	private boolean secureConnection = false; //whether or not we are using SSL
	private int operationTimeout = 5000; //default timeout for operations (in ms)



	/* logging options */
	private boolean logAuthSuccess = false;  // log successful authentication
	private boolean logAuthFailure = true;   // log unsuccessful authentication

	/* Hashmap of attribute mappings */
	private HashMap attributeMappings = new HashMap();

	/* Hashtable of users that have successfully logged in...
	 * we pull their details from here instead of the directory on subsequent requests
	 * we will also expire their details after a default five minutes or so
	 */
	private Hashtable users = new Hashtable();

	/* Dependency: logging service */  	
	private static Log m_logger = LogFactory.getLog(JLDAPDirectoryProvider.class);

	/** Dependency: SqlService */
	protected SqlService m_sqlService = null;

	/** Configuration: Cache TTL for positive auth caching (ms, defaults to 5 minutes) */
	protected int m_cachettl = 5 * 60 * 1000;

	/** Configuration: Cache TTL for negative auth caching (ms, defaults to 30 seconds) */
	protected int m_cachettlf = 30 * 1000;

	protected ServerConfigurationService m_sService = null;

	public JLDAPDirectoryProvider(){
		attributeMappings.put("login","cn");
		attributeMappings.put("firstName","givenName");
		attributeMappings.put("lastName","sn");
		attributeMappings.put("email","email");
		attributeMappings.put("groupMembership","groupMembership");
		attributeMappings.put("distinguishedName","dn");	
	}

	public void setSqlService(SqlService service)
	{
		m_sqlService = service;
	}

	public void setServerConfigurationService(ServerConfigurationService service)
	{
		m_sService = service;
	}

	private UserAliasLogic userAliasLogic;
	public void setUserAliasLogic(UserAliasLogic ual) {
		userAliasLogic = ual;
	}

	private SiteService siteService;
	public void setSiteService(SiteService ss) {
		siteService = ss;
	}

	public void init()  
	{     
		try   {
			m_logger.info(this +".init()");               
			// set keystore location for SSL (if we are using it)
			if(isSecureConnection()){
				if (getKeystoreLocation() != null) {
					//	System.setProperty("javax.net.ssl.trustStore", getKeystoreLocation());
					//	System.setProperty("javax.net.ssl.trustStorePassword", getKeystorePassword());
				}
				m_logger.debug("Keystore is at: " + System.getenv("javax.net.ssl.trustStore"));
				LDAPSocketFactory ssf = new LDAPJSSESecureSocketFactory();
				LDAPConnection.setSocketFactory(ssf);
			}
		}  
		catch (Throwable t) {m_logger.warn(this +".init(): ", t);}  
	}

	public void destroy() 
	{       
		m_logger.info(this +".destroy()");   
	}

	public boolean authenticateUser(String userLogin, UserEdit edit, String password){
		m_logger.debug(this +".authenticateUser(): " + userLogin); 

		// Don't use LDAP auth if the userLogin contains '@' or is admin or contains * the LDAP wildecard
		if ((userLogin.indexOf("@") != -1) || userLogin.equals("admin") || userLogin.equals("*")|| userLogin.equalsIgnoreCase(("guest"))) 
		{
			// Thread.sleep(500);
			return false;
		}

		// make sure password contains some value
		if (password.length() == 0){
			if (logAuthFailure) 
			{
				m_logger.debug("Authentication failed (blank password) for " + userLogin); 
			}
			return false;
		}

		UserData existingUser = (UserData) users.get(userLogin);

		boolean authUser = false;
		String hpassword = encodeSHA(password);

		// Check for user in in-memory hashtable. To return a positive or negative hit from the cache,
		// these conditions must be met:
		//
		// 1) an entry for the userId must exist in the cache
		// 2) the last successful authentication was < cachettl milliseconds ago, or
		// 3) the last failed authentication was < cachettlf milliseconds ago
		// 4) the one-way hash of the entered password must be equivalent to what is stored in the cache
		//
		// If these conditions are not, the authentication is performed via LDAP and the result is cached
		try {	
			if (existingUser == null 
					|| ((System.currentTimeMillis() - existingUser.getTimeStamp()) > m_cachettl && existingUser.authSuccess && existingUser.getHpw().equals(hpassword))
					|| ((System.currentTimeMillis() - existingUser.getTimeStamp()) > m_cachettlf && !existingUser.authSuccess && existingUser.getHpw().equals(hpassword))
					|| !(existingUser.getHpw().equals(hpassword)) )
			{

				// remove any references to the user from the hashtable
				users.remove(userLogin);

				// create new ldap connection
				LDAPConnection conn = new LDAPConnection();	
				LDAPConstraints cons = new LDAPConstraints();

				cons.setTimeLimit(operationTimeout);			
				conn.setConstraints(cons);

				// filter to find user
				String sFilter = (String)attributeMappings.get("login") + "=" + userLogin;

				// string to hold dn
				String thisDn = "";

				// string array of attribs to get from the directory
				String[] attrList = new String[] {	
						(String)attributeMappings.get("distinguishedName"),
						"objectClass",
						"aliasedObjectName",
						"loginDisabled"
				};

				try{
					// connect to ldap server
					conn.connect( ldapHost, ldapPort );

					// get entry from directory
					LDAPEntry userEntry = getEntryFromDirectory(sFilter,attrList,conn);

					// check that user exists in directory
					if (userEntry == null)
					{
						if (logAuthFailure)
						{
							m_logger.info("Authentication failed for " + userLogin + ": not found in LDAP directory");
						}
						conn.disconnect();
						return false;
					}

					// Disable for now - NPEs on student accounts
					/*
					 else if ("true".equalsIgnoreCase(userEntry.getAttribute("loginDisabled").getStringValue())) {
						if (logAuthFailure)
						{
						 	m_logger.info("Authentication failed for " + userLogin + ": Account Disabled");
						}
						conn.disconnect();
						return false;

					}
					 */

					// if this object is an alias use the aliased object to auth
					LDAPAttribute objectClass = userEntry.getAttribute("objectClass");

					if (objectClass.getStringValue().equals("aliasObject"))
					{
						LDAPAttribute aliasDN = userEntry.getAttribute("aliasedObjectName");
						thisDn =  aliasDN.getStringValue();		
					} else {
						thisDn = userEntry.getDN();
					}

					// attempt to bind to the directory... failure here probably means bad login/password
					conn.bind(LDAPConnection.LDAP_V3,
							thisDn,
							password.getBytes("UTF8"));

					conn.disconnect();

					if (logAuthSuccess)
					{
						m_logger.info("Authenticated " + userLogin + " (" + thisDn + ") from LDAP");
					}		

					//seing these are now diferent servers we no longer set this here
					//Session session = SessionManager.getCurrentSession();
					// session.setAttribute("netPasswd",password);		
					//session.setAttribute("netDn",thisDn);

					// create entry for authenticated user in cache
					UserData u = new UserData(); 
					u.setId(userLogin);
					u.setHpw(hpassword);
					u.setTimeStamp(System.currentTimeMillis());
					u.setAuthSuccess(true);

					// put entry for authenticated user into cache
					users.put(userLogin, u);

					return true;
				}
				catch(Exception e)
				{
					if (logAuthFailure)
					{
						m_logger.info("Authentication failed for " + userLogin + " (" + thisDn + "): " + e.toString());
					}

					// create entry for user failed authenticatation in cache
					UserData u = new UserData(); 
					u.setId(userLogin);
					u.setHpw(hpassword);
					u.setTimeStamp(System.currentTimeMillis());
					u.setAuthSuccess(false);

					// put entry for authenticated user into cache
					users.put(userLogin, u);

					return false;
				}
			}
			else
			{
				// Valid cache entry
				authUser = existingUser.getAuthSuccess();

				if (authUser && logAuthSuccess) {
					m_logger.info("Authenticated " + userLogin + " from auth cache");
				}

				if (!authUser && logAuthFailure) {
					m_logger.info("Authentication failed for " + userLogin + ": matched invalid password from auth cache");				
				}

				return authUser;
			}

		}
		catch (Exception e)
		{
			m_logger.warn("authenticateUser(): exception: " + e);
			return false;
		}
	}

	public void destroyAuthentication() {
		// not sure what to do here
	}


	public boolean findUserByEmail(UserEdit edit, String email) {
		return false;
	}

	public boolean getUser(UserEdit edit) {

		// always return false as we're only using LDAP for authentication
		m_logger.debug(this +".getUser() from LDAP directory: "+edit.getId());
		return false;
	}

	/**
	 * Access a collection of UserEdit objects; if the user is found, update the information, otherwise remove the UserEdit object from the collection.
	 * @param users The UserEdit objects (with id set) to fill in or remove.
	 */
	public void getUsers(Collection users)
	{
		// TODO: is there a more efficient multi-user LDAP call to use instead of this iteration?
		for (Iterator i = users.iterator(); i.hasNext();)
		{
			UserEdit user = (UserEdit) i.next();
			if (!getUser(user))
			{
				i.remove();
			}
		}
	}

	public boolean updateUserAfterAuthentication() {
		return false;
	}

	public boolean userExists(String id) {
		UserData existingUser = (UserData)users.get(id);

		if(existingUser != null){
			return true;
		}
		LDAPConnection conn = new LDAPConnection();
		String sFilter = (String)attributeMappings.get("login") + "=" + id;

		String thisDn = "";
		String[] attrList = new String[] { (String)attributeMappings.get("distinguishedName") };
		try{
			conn.connect( ldapHost, ldapPort );
			//this will fail if user does not exist	
			LDAPEntry userEntry = getEntryFromDirectory(sFilter,attrList,conn);			
			conn.disconnect();
		}
		catch(Exception e)
		{
			return false;	
		}		
		return true;
	}

	// search the directory to get an entry
	private LDAPEntry getEntryFromDirectory(String searchFilter, String[] attribs, LDAPConnection conn)
	throws LDAPException
	{
		LDAPEntry nextEntry = null;
		LDAPSearchConstraints cons = new LDAPSearchConstraints();
		cons.setDereference(LDAPSearchConstraints.DEREF_NEVER);		
		cons.setTimeLimit(operationTimeout);

		LDAPSearchResults searchResults =
			conn.search(getBasePath(),
					LDAPConnection.SCOPE_SUB,
					searchFilter,
					attribs,
					false,
					cons);

		if(searchResults.hasMore()){
			nextEntry = searchResults.next();            
		}

		return nextEntry;
	}


	/**
	 * @return Returns the ldapHost.
	 */
	public String getLdapHost() {
		return ldapHost;
	}
	/**
	 * @param ldapHost The ldapHost to set.
	 */
	public void setLdapHost(String ldapHost) {
		this.ldapHost = ldapHost;
	}
	/**
	 * @return Returns the ldapPort.
	 */
	public int getLdapPort() {
		return ldapPort;
	}
	/**
	 * @param ldapPort The ldapPort to set.
	 */
	public void setLdapPort(int ldapPort) {
		this.ldapPort = ldapPort;
	}

	/**
	 * @return Returns the secureConnection.
	 */
	public boolean isSecureConnection() {
		return secureConnection;
	}
	/**
	 * @param secureConnection The secureConnection to set.
	 */
	public void setSecureConnection(boolean secureConnection) {
		this.secureConnection = secureConnection;
	}

	/**
	 * @param logAuthSuccess Log authentication successes.
	 */
	public void setLogAuthSuccess(String value) {
		try
		{
			this.logAuthSuccess = new Boolean(value).booleanValue();
		}
		catch (Exception any)
		{
			m_logger.warn("Invalid value setting logAuthSuccess: " + value);
		}
	}


	/**
	 * @param logAuthFailure Log authentication failures.
	 */
	public void setLogAuthFailure(String value) {
		try
		{
			this.logAuthFailure = new Boolean(value).booleanValue();
		}
		catch (Exception any)
		{
			m_logger.warn("Invalid value setting logAuthFailure: " + value);
		}
	}

	/**
	 * @return Returns the keystoreLocation.
	 */
	public String getKeystoreLocation() {
		return keystoreLocation;
	}
	/**
	 * @param keystoreLocation The keystoreLocation to set.
	 */
	public void setKeystoreLocation(String keystoreLocation) {
		this.keystoreLocation = keystoreLocation;
	}
	/**
	 * @return Returns the keystorePassword.
	 */
	public String getKeystorePassword() {
		return keystorePassword;
	}
	/**
	 * @param keystorePassword The keystorePassword to set.
	 */
	public void setKeystorePassword(String keystorePassword) {
		this.keystorePassword = keystorePassword;
	}

	/**
	 * @return Returns the basePath.
	 */
	public String getBasePath() {
		return basePath;
	}
	/**
	 * @param basePath The basePath to set.
	 */
	public void setBasePath(String basePath) {
		this.basePath = basePath;
	}

	//helper class for storing user data in the hashtable cache
	class UserData{
		String id;
		String firstName;
		String lastName;
		String email;
		String type;
		String hpw;
		boolean authSuccess;
		long timeStamp;

		/**
		 * @return whether the user susscefully authenticated
		 */
		public boolean getAuthSuccess() {
			return authSuccess;
		}

		/**
		 * @param boolean - has the user succesfully authenticated
		 */
		public void setAuthSuccess(boolean value)
		{
			this.authSuccess = value;
		}

		/**
		 * @return Returns the email.
		 */
		public String getEmail() {
			return email;
		}
		/**
		 * @param email The email to set.
		 */
		public void setEmail(String email) {
			this.email = email;
		}
		/**
		 * @return Returns the firstName.
		 */
		public String getFirstName() {
			return firstName;
		}
		/**
		 * @param firstName The firstName to set.
		 */
		public void setFirstName(String firstName) {
			this.firstName = firstName;
		}
		/**
		 * @return Returns the id.
		 */
		public String getId() {
			return id;
		}
		/**
		 * @param id The id to set.
		 */
		public void setId(String id) {
			this.id = id;
		}
		/**
		 * @return Returns the lastName.
		 */
		public String getLastName() {
			return lastName;
		}
		/**
		 * @param lastName The lastName to set.
		 */
		public void setLastName(String lastName) {
			this.lastName = lastName;
		}
		/**
		 * @return Returns the type.
		 */
		public String getType() {
			return type;
		}
		/**
		 * @param type The type to set.
		 */
		public void setType(String type) {
			this.type = type;
		}

		/**
		 * @param hpw
		 *        hashed pw to put in.
		 */
		public void setHpw(String hpw)
		{
			this.hpw = hpw;
		}

		/**
		 * @return Returns the hashed password.
		 */

		public String getHpw()
		{
			return hpw;
		}
		/**
		 * @return Returns the timeStamp.
		 */
		public long getTimeStamp() {
			return timeStamp;
		}
		/**
		 * @param timeStamp The timeStamp to set.
		 */
		public void setTimeStamp(long timeStamp) {
			this.timeStamp = timeStamp;
		}
	}

	/**
	 * <p>
	 * Hash string for storage in a cache using SHA
	 * </p>
	 * 
	 * @param UTF-8
	 *        string
	 * @return encoded hash of string
	 */

	private synchronized String encodeSHA(String plaintext)
	{

		try
		{
			MessageDigest md = MessageDigest.getInstance("SHA");
			md.update(plaintext.getBytes("UTF-8"));
			byte raw[] = md.digest();
			String hash = (new BASE64Encoder()).encode(raw);
			return hash;
		}
		catch (Exception e)
		{
			m_logger.warn("encodeSHA(): exception: " + e);
			return null;
		}
	} // encodeSHA

	/**
	 * @param timeMs The m_cachettl to set.
	 */
	public void setCacheTTL(int timeMs) {
		m_cachettl = timeMs;
	}

	/**
	 * @param timeMs The m_cachettlf to set.
	 */
	public void setCacheTTLF(int timeMs) {
		m_cachettlf = timeMs;
	}

	/**
	 * @return Returns the attributeMappings.
	 */
	public Map getAttributeMappings() {
		return attributeMappings;
	}
	/**
	 * @param attributeMappings The attributeMappings to set.
	 */
	public void setAttributeMappings(Map attributeMappings) {
		this.attributeMappings = (HashMap)attributeMappings;
	}
	/**
	 * @return Returns the operationTimeout.
	 */
	public int getOperationTimeout() {
		return operationTimeout;
	}
	/**
	 * @param operationTimeout The operationTimeout to set.
	 */
	public void setOperationTimeout(int operationTimeout) {
		this.operationTimeout = operationTimeout;
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean authenticateWithProviderFirst(String id)
	{
		return false;
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean createUserRecord(String id)
	{
		return false;
	}

	// display Advisor methods
	public String getDisplayId(User user)
	{
		return null;

	}

	public String getDisplayName(User user) 
	{

		m_logger.debug("getDisplayUser(" + user.getId() + ")");
		if (m_sService.getBoolean("udp.useUserAlias", false) ) {
			try {
				Placement placement = ToolManager.getCurrentPlacement();
				String presentSiteId = null; 
				if ( placement != null && placement.getContext() != null) {
					presentSiteId = "/site/" + placement.getContext();
				} else {
					m_logger.info("Context not available for getDisplayName: " + user.getEid());
					return null;
				}
				

				if (presentSiteId != null && userAliasLogic.realmIsAliased(presentSiteId)) {
					UserAliasItem ua = userAliasLogic.getUserAliasItemByIdForContext(user.getId(), presentSiteId);
					if (ua != null && (ua.getFirstName() != null || ua.getLastName() != null )) {
						String fn = "";
						if (ua.getFirstName() != null)
							fn = ua.getFirstName();
						String ln = "";
						if (ua.getLastName() != null)
							ln = ua.getLastName();

						return fn + " " + ln;
					}
				}

			}
			catch (Exception e) {
				m_logger.warn("getDisplayName(User user) Cannot resolve name: " + e.toString());
				if (m_logger.isDebugEnabled())
					e.printStackTrace();
			}
		}
		return null;



	}

	public String getDisplayName(User user, String context) {
		m_logger.debug("getDisplayName(" + user.getId() + " , " + context +")");
		//this is a realm id not a site id
		if (!context.startsWith("/site/"));
			context="/site/" + context;

		if (m_sService.getBoolean("udp.useUserAlias", false) && userAliasLogic.realmIsAliased(context) ) {
			try {
				UserAliasItem ua = userAliasLogic.getUserAliasItemByIdForContext(user.getId(), context);
				if (ua != null && (ua.getFirstName() != null || ua.getLastName() != null )) {
					String fn = "";
					if (ua.getFirstName() != null)
						fn = ua.getFirstName();
					String ln = "";
					if (ua.getLastName() != null)
						ln = ua.getLastName();

					return fn + " " + ln;
				}

			}
			catch (Exception e) {
				m_logger.warn("getDisplayName(User user, String Context) Cannot resolve name: " + e.toString());
				if (m_logger.isDebugEnabled())
					e.printStackTrace();
			}
		}
		return null;
	}

}
