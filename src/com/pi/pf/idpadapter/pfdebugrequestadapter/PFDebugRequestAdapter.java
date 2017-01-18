package com.pi.pf.idpadapter.pfdebugrequestadapter;

import java.io.IOException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.saml20.adapter.AuthnAdapterException;
import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.gui.AdapterConfigurationGuiDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;
import org.sourceid.saml20.adapter.idp.authn.AuthnPolicy;
import org.sourceid.saml20.adapter.idp.authn.IdpAuthenticationAdapter;
import org.sourceid.saml20.adapter.idp.authn.IdpAuthnAdapterDescriptor;

import com.pingidentity.sdk.AuthnAdapterResponse;
import com.pingidentity.sdk.AuthnAdapterResponse.AUTHN_STATUS;
import com.pingidentity.sdk.IdpAuthenticationAdapterV2;

/**
 * <p>
 * Logs the HTTP request data and the data passed in the inParamenter argument. Always returns a AUTHN_STATUS.SUCCESS with
 * an empty username parameter. Must be chained to other adapters.
 * </p>
 */
public class PFDebugRequestAdapter implements IdpAuthenticationAdapterV2 {

	private final IdpAuthnAdapterDescriptor descriptor;
	private final Log log = LogFactory.getLog(this.getClass());
	private final String userNameAttribute = "username";
	
	/**
	 * Initializes the authentication adapter descriptor so PingFederate can
	 * generate the proper configuration GUI
	 */
	public PFDebugRequestAdapter() {

		// Create a GUI descriptor
		AdapterConfigurationGuiDescriptor guiDescriptor = new AdapterConfigurationGuiDescriptor("Define this string");

		// Create the Idp authentication adapter descriptor
		Set<String> contract = new HashSet<String>();
		contract.add(userNameAttribute);
		descriptor = new IdpAuthnAdapterDescriptor(this, "Debug request adapter", contract, false, guiDescriptor, false);
	}

	/**
	 * The PingFederate server will invoke this method on your adapter
	 * implementation to discover metadata about the implementation. This
	 * included the adapter's attribute contract and a description of what
	 * configuration fields to render in the GUI. <br/>
	 * <br/>
	 * Your implementation of this method should return the same
	 * IdpAuthnAdapterDescriptor object from call to call - behaviour of the
	 * system is undefined if this convention is not followed.
	 * 
	 * @return an IdpAuthnAdapterDescriptor object that describes this IdP
	 *         adapter implementation.
	 */
	public IdpAuthnAdapterDescriptor getAdapterDescriptor() {
		return descriptor;
	}

	/**
	 * This is the method that the PingFederate server will invoke during
	 * processing of a single logout to terminate a security context for a user
	 * at the external application or authentication provider service.
	 * <p>
	 * If your implementation of this method needs to operate asynchronously, it
	 * just needs to write to the HttpServletResponse as appropriate and commit
	 * it. Right after invoking this method the PingFederate server checks to
	 * see if the response has been committed. If the response has been
	 * committed, PingFederate saves the state it needs and discontinues
	 * processing for the current transaction. Processing of the transaction is
	 * continued when the user agent returns to the <code>resumePath</code> at
	 * the PingFederate server at which point the server invokes this method
	 * again. This series of events will be repeated until this method returns
	 * without committing the response. When that happens (which could be the
	 * first invocation) PingFederate will complete the protocol transaction
	 * processing with the return result of this method.
	 * </p>
	 * <p>
	 * Note that if the response is committed, then PingFederate ignores the
	 * return value. Only the return value of an invocation that does not commit
	 * the response will be used. Accessing the HttpSession from the request is
	 * not recommended and doing so is deprecated. Use
	 * {@link org.sourceid.saml20.adapter.state.SessionStateSupport} as an
	 * alternative.
	 * </p>
	 * <p>
	 * 
	 * <b>Note on SOAP logout:</b> If this logout is being invoked as the result
	 * of a back channel protocol request, the request, response and resumePath
	 * parameters will all be null as they have no meaning in such a context
	 * where the user agent is inaccessible.
	 * </p>
	 * <p>
	 * In this example, no extra action is needed to logout so simply return
	 * true.
	 * </p>
	 * 
	 * @param authnIdentifiers
	 *            the map of authentication identifiers originally returned to
	 *            the PingFederate server by the {@link #lookupAuthN} method.
	 *            This enables the adapter to associate a security context or
	 *            session returned by lookupAuthN with the invocation of this
	 *            logout method.
	 * @param req
	 *            the HttpServletRequest can be used to read cookies,
	 *            parameters, headers, etc. It can also be used to find out more
	 *            about the request like the full URL the request was made to.
	 * @param resp
	 *            the HttpServletResponse. The response can be used to
	 *            facilitate an asynchronous interaction. Sending a client side
	 *            redirect or writing (and flushing) custom content to the
	 *            response are two ways that an invocation of this method allows
	 *            for the adapter to take control of the user agent. Note that
	 *            if control of the user agent is taken in this way, then the
	 *            agent must eventually be returned to the
	 *            <code>resumePath</code> endpoint at the PingFederate server to
	 *            complete the protocol transaction.
	 * @param resumePath
	 *            the relative URL that the user agent needs to return to, if
	 *            the implementation of this method invocation needs to operate
	 *            asynchronously. If this method operates synchronously, this
	 *            parameter can be ignored. The resumePath is the full path
	 *            portion of the URL - everything after hostname and port. If
	 *            the hostname, port, or protocol are needed, they can be
	 *            derived using the HttpServletRequest.
	 * @return a boolean indicating if the logout was successful.
	 * @throws AuthnAdapterException
	 *             for any unexpected runtime problem that the implementation
	 *             cannot handle.
	 * @throws IOException
	 *             for any problem with I/O (typically any operation that writes
	 *             to the HttpServletResponse will throw an IOException.
	 * 
	 * @see IdpAuthenticationAdapter#logoutAuthN(Map, HttpServletRequest,
	 *      HttpServletResponse, String)
	 */
	@SuppressWarnings("rawtypes")
	public boolean logoutAuthN(Map authnIdentifiers, HttpServletRequest req, HttpServletResponse resp, String resumePath) throws AuthnAdapterException,
			IOException {
		return true;
	}

	/**
	 * This method is called by the PingFederate server to push configuration
	 * values entered by the administrator via the dynamically rendered GUI
	 * configuration screen in the PingFederate administration console. Your
	 * implementation should use the {@link Configuration} parameter to
	 * configure its own internal state as needed. The tables and fields
	 * available in the Configuration object will correspond to the tables and
	 * fields defined on the
	 * {@link org.sourceid.saml20.adapter.gui.AdapterConfigurationGuiDescriptor}
	 * on the AuthnAdapterDescriptor returned by the
	 * {@link #getAdapterDescriptor()} method of this class. <br/>
	 * <br/>
	 * Each time the PingFederate server creates a new instance of your adapter
	 * implementation this method will be invoked with the proper configuration.
	 * All concurrency issues are handled in the server so you don't need to
	 * worry about them here. The server doesn't allow access to your adapter
	 * implementation instance until after creation and configuration is
	 * completed.
	 * 
	 * @param configuration
	 *            the Configuration object constructed from the values entered
	 *            by the user via the GUI.
	 */
	public void configure(Configuration configuration) {
	}

	/**
	 * This method is used to retrieve information about the adapter (e.g.
	 * AuthnContext).
	 * <p>
	 * In this example the method not used, return null
	 * </p>
	 * 
	 * @return a map
	 */
	public Map<String, Object> getAdapterInfo() {
		return null;
	}

	/**
	 * This is an extended method that the PingFederate server will invoke
	 * during processing of a single sign-on transaction to lookup information
	 * about an authenticated security context or session for a user at the
	 * external application or authentication provider service.
	 * <p>
	 * If your implementation of this method needs to operate asynchronously, it
	 * just needs to write to the HttpServletResponse as appropriate and commit
	 * it. Right after invoking this method the PingFederate server checks to
	 * see if the response has been committed. If the response has been
	 * committed, PingFederate saves the state it needs and discontinues
	 * processing for the current transaction. Processing of the transaction is
	 * continued when the user agent returns to the <code>resumePath</code> at
	 * the PingFederate server at which point the server invokes this method
	 * again. This series of events will be repeated until this method returns
	 * without committing the response. When that happens (which could be the
	 * first invocation) PingFederate will complete the protocol transaction
	 * processing with the return result of this method.
	 * </p>
	 * <p>
	 * Note that if the response is committed, then PingFederate ignores the
	 * return value. Only the return value of an invocation that does not commit
	 * the response will be used.
	 * </p>
	 * <p>
	 * If this adapter is implemented asynchronously, it's recommended that the
	 * user agent always returns to the <code>
	 * resumePath</code> in order to be compatible with Composite Adapter's
	 * "Sufficent" adapter chaining policy. The Composite Adapter allows an
	 * Administrator to "chain" a selection of available adapter instances for a
	 * connection. At runtime, adapter chaining means that SSO requests are
	 * passed sequentially through each adapter instance specified until one or
	 * more authentication results are found for the user. If the user agent
	 * does not return control to PingFederate for failed authentication
	 * scenarios, then the authentication chain will break and should not be
	 * used with Composite Adapter's "Sufficient" chaining policy.
	 * </p>
	 * <p>
	 * In this example, we determine if the client (or the last proxy) is on the
	 * configured subnet. If the client has an IPv6 address that's not ::1, fail
	 * immediately. If the user was previously authenticated by another adapter
	 * assign it a corporate role, otherwise use the guest role.
	 * </p>
	 * 
	 * @param req
	 *            the HttpServletRequest can be used to read cookies,
	 *            parameters, headers, etc. It can also be used to find out more
	 *            about the request like the full URL the request was made to.
	 *            Accessing the HttpSession from the request is not recommended
	 *            and doing so is deprecated. Use
	 *            {@link org.sourceid.saml20.adapter.state.SessionStateSupport}
	 *            as an alternative.
	 * @param resp
	 *            the HttpServletResponse. The response can be used to
	 *            facilitate an asynchronous interaction. Sending a client side
	 *            redirect or writing (and flushing) custom content to the
	 *            response are two ways that an invocation of this method allows
	 *            for the adapter to take control of the user agent. Note that
	 *            if control of the user agent is taken in this way, then the
	 *            agent must eventually be returned to the
	 *            <code>resumePath</code> endpoint at the PingFederate server to
	 *            complete the protocol transaction.
	 * @param inParameters
	 *            A map that contains a set of input parameters. The input
	 *            parameters provided are detailed in
	 *            {@link IdpAuthenticationAdapterV2}, prefixed with
	 *            <code>IN_PARAMETER_NAME_*</code> i.e.
	 *            {@link IdpAuthenticationAdapterV2#IN_PARAMETER_NAME_RESUME_PATH}
	 *            .
	 * @return {@link AuthnAdapterResponse} The return value should not be null.
	 * @throws AuthnAdapterException
	 *             for any unexpected runtime problem that the implementation
	 *             cannot handle.
	 * @throws IOException
	 *             for any problem with I/O (typically any operation that writes
	 *             to the HttpServletResponse).
	 */
	@SuppressWarnings("unchecked")
	public AuthnAdapterResponse lookupAuthN(HttpServletRequest req, HttpServletResponse resp, Map<String, Object> inParameters) throws AuthnAdapterException,
			IOException {

		log.info("**** PFDebugRequestAdapter: start");
		AuthnAdapterResponse authnAdapterResponse = new AuthnAdapterResponse();

		Map<String,Object> outAttributes = new HashMap<String, Object>();
		outAttributes.put (userNameAttribute,"");
		
		logHttpRequest(req);
		
		log.info("**** inParameters: " + inParameters.toString());
		authnAdapterResponse.setAuthnStatus(AUTHN_STATUS.SUCCESS);
		authnAdapterResponse.setAttributeMap(outAttributes);
		log.info("**** PFDebugRequestAdapter: end");
		return authnAdapterResponse;
	}

	/**
	 * This method is deprecated. It is not called when
	 * IdpAuthenticationAdapterV2 is implemented. It is replaced by
	 * {@link #lookupAuthN(HttpServletRequest, HttpServletResponse, Map)}
	 * 
	 * @deprecated
	 */
	@SuppressWarnings(value = { "rawtypes" })
	public Map lookupAuthN(HttpServletRequest req, HttpServletResponse resp, String partnerSpEntityId, AuthnPolicy authnPolicy, String resumePath)
			throws AuthnAdapterException, IOException {
		throw new UnsupportedOperationException();
	}
	
	
	
	
	private void logHttpRequest (HttpServletRequest httpRequest) {
        log.info("**** Request " + httpRequest.getMethod() + " for "+ httpRequest.getRequestURI());

        log.info("**** Headers");
        Enumeration headerNames = httpRequest.getHeaderNames();
        while(headerNames.hasMoreElements()) {
            String headerName = (String)headerNames.nextElement();
            log.info(headerName + " = " + httpRequest.getHeader(headerName));
        }

        log.info("**** Parameters");
        Enumeration params = httpRequest.getParameterNames();
        while(params.hasMoreElements()){
            String paramName = (String)params.nextElement();
            log.info(paramName + " = " + httpRequest.getParameter(paramName));
        }
    }

    

}