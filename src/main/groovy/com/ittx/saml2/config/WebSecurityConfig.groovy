package com.ittx.saml2.config

import com.ittx.saml2.service.SAMLUserDetailsServiceImpl
import org.apache.commons.httpclient.HttpClient
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager
import org.apache.velocity.app.VelocityEngine
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider
import org.opensaml.saml2.metadata.provider.MetadataProvider
import org.opensaml.saml2.metadata.provider.MetadataProviderException
import org.opensaml.xml.parse.ParserPool
import org.opensaml.xml.parse.StaticBasicParserPool
import org.springframework.beans.factory.DisposableBean
import org.springframework.beans.factory.InitializingBean
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.io.DefaultResourceLoader
import org.springframework.core.io.Resource
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.saml.*
import org.springframework.security.saml.context.SAMLContextProviderImpl
import org.springframework.security.saml.key.JKSKeyManager
import org.springframework.security.saml.key.KeyManager
import org.springframework.security.saml.log.SAMLDefaultLogger
import org.springframework.security.saml.metadata.*
import org.springframework.security.saml.parser.ParserPoolHolder
import org.springframework.security.saml.processor.*
import org.springframework.security.saml.util.VelocityFactory
import org.springframework.security.saml.websso.*
import org.springframework.security.web.DefaultSecurityFilterChain
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.access.channel.ChannelProcessingFilter
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler
import org.springframework.security.web.authentication.logout.LogoutHandler
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import org.springframework.security.web.csrf.CsrfFilter
import org.springframework.security.web.util.matcher.AntPathRequestMatcher

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
class WebSecurityConfig extends WebSecurityConfigurerAdapter implements InitializingBean, DisposableBean {

    private Timer backgroundTaskTimer
    private MultiThreadedHttpConnectionManager multiThreadedHttpConnectionManager

    void init() {
        this.backgroundTaskTimer = new Timer(true)
        this.multiThreadedHttpConnectionManager = new MultiThreadedHttpConnectionManager()
    }

    void shutdown() {
        this.backgroundTaskTimer.purge()
        this.backgroundTaskTimer.cancel()
        this.multiThreadedHttpConnectionManager.shutdown()
    }

    @Autowired
    private SAMLUserDetailsServiceImpl samlUserDetailsServiceImpl

    // Initialization of the velocity engine
    @Bean
    VelocityEngine velocityEngine() {
        return VelocityFactory.getEngine()
    }

    //OpenSAML XML解析池
    @Bean(initMethod = "initialize")
    StaticBasicParserPool parserPool() {
        return new StaticBasicParserPool()
    }

    //解析池
    @Bean(name = "parserPoolHolder")
    ParserPoolHolder parserPoolHolder() {
        return new ParserPoolHolder()
    }

    // Bindings, encoders and decoders used for creating and parsing messages
    // 用于创建和解析消息的绑定，编码器和解码器
    @Bean
    HttpClient httpClient() {
        return new HttpClient(this.multiThreadedHttpConnectionManager)
    }

    // SAML Authentication Provider responsible for validating of received SAML
    // SAML身份验证提供程序，负责验证收到的SAML
    // messages
    @Bean
    SAMLAuthenticationProvider samlAuthenticationProvider() {
        SAMLAuthenticationProvider samlAuthenticationProvider = new SAMLAuthenticationProvider()
        samlAuthenticationProvider.setUserDetails(samlUserDetailsServiceImpl)
        samlAuthenticationProvider.setForcePrincipalAsString(false)
        return samlAuthenticationProvider
    }

    // Provider of default SAML Context
    // 默认SAML上下文的提供者
    @Bean
    SAMLContextProviderImpl contextProvider() {
        return new SAMLContextProviderImpl()
    }

    // Initialization of OpenSAML library
    @Bean
    static SAMLBootstrap sAMLBootstrap() {
        return new SAMLBootstrap()
    }

    // Logger for SAML messages and events
    @Bean
    SAMLDefaultLogger samlLogger() {
        return new SAMLDefaultLogger()
    }

    // SAML 2.0 WebSSO Assertion Consumer
    @Bean
    WebSSOProfileConsumer webSSOprofileConsumer() {
        return new WebSSOProfileConsumerImpl()
    }

    // SAML 2.0 Holder-of-Key WebSSO Assertion Consumer
    @Bean
    WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
        return new WebSSOProfileConsumerHoKImpl()
    }

    // SAML 2.0 Web SSO profile
    @Bean
    WebSSOProfile webSSOprofile() {
        return new WebSSOProfileImpl()
    }

    // SAML 2.0 Holder-of-Key Web SSO profile
    @Bean
    WebSSOProfileConsumerHoKImpl hokWebSSOProfile() {
        return new WebSSOProfileConsumerHoKImpl()
    }

    // SAML 2.0 ECP profile
    @Bean
    WebSSOProfileECPImpl ecpprofile() {
        return new WebSSOProfileECPImpl()
    }

    @Bean
    SingleLogoutProfile logoutprofile() {
        return new SingleLogoutProfileImpl()
    }

    // Central storage of cryptographic keys
    @Bean
    KeyManager keyManager() {
        DefaultResourceLoader loader = new DefaultResourceLoader()
        Resource storeFile = loader.getResource("classpath:/saml/samlKeystore.jks")
        String storePass = "nalle123"
        Map<String, String> passwords = new HashMap<String, String>()
        passwords.put("apollo", "nalle123")
        String defaultKey = "apollo"
        return new JKSKeyManager(storeFile, storePass, passwords, defaultKey)
    }

    @Bean
    WebSSOProfileOptions defaultWebSSOProfileOptions() {
        WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions()
        webSSOProfileOptions.setIncludeScoping(false)
        return webSSOProfileOptions
    }

    // Entry point to initialize authentication, default values taken from
    // properties file
    @Bean
    SAMLEntryPoint samlEntryPoint() {
        SAMLEntryPoint samlEntryPoint = new SAMLEntryPoint()
        samlEntryPoint.setDefaultProfileOptions(defaultWebSSOProfileOptions())
        return samlEntryPoint
    }

    // Setup advanced info about metadata
    @Bean
    ExtendedMetadata extendedMetadata() {
        ExtendedMetadata extendedMetadata = new ExtendedMetadata()
        extendedMetadata.setIdpDiscoveryEnabled(true)
        extendedMetadata.setSigningAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
        extendedMetadata.setSignMetadata(true)
        extendedMetadata.setEcpEnabled(true)
        return extendedMetadata
    }

    // IDP Discovery Service
    // IDP发现服务
    @Bean
    SAMLDiscovery samlIDPDiscovery() {
        SAMLDiscovery idpDiscovery = new SAMLDiscovery()
        idpDiscovery.setIdpSelectionPath("/saml/discovery")
        return idpDiscovery
    }

    @Bean
    @Qualifier("idp-ssocircle")
    ExtendedMetadataDelegate ssoCircleExtendedMetadataProvider()
            throws MetadataProviderException {
        String idpSSOCircleMetadataURL = "https://idp.ssocircle.com/meta-idp.xml"
        //String idpSSOCircleMetadataURL = "http://127.0.0.1:8888/xml/IDP_ITE_metadata_2020.xml"
        HTTPMetadataProvider httpMetadataProvider = new HTTPMetadataProvider(
                this.backgroundTaskTimer, httpClient(), idpSSOCircleMetadataURL)
        httpMetadataProvider.setParserPool(parserPool())
        ExtendedMetadataDelegate extendedMetadataDelegate =
                new ExtendedMetadataDelegate(httpMetadataProvider, extendedMetadata())
        extendedMetadataDelegate.setMetadataTrustCheck(true)
        extendedMetadataDelegate.setMetadataRequireSignature(false)
        backgroundTaskTimer.purge()
        return extendedMetadataDelegate
    }

    // IDP Metadata configuration - paths to metadata of IDPs in circle of trust
    // is here
    // Do no forget to call iniitalize method on providers
    @Bean
    @Qualifier("metadata")
    CachingMetadataManager metadata() throws MetadataProviderException {
        List<MetadataProvider> providers = new ArrayList<MetadataProvider>()
        providers.add(ssoCircleExtendedMetadataProvider())
        return new CachingMetadataManager(providers)
    }

    // Filter automatically generates default SP metadata
    // 筛选器自动生成默认的SP元数据
    @Bean
    MetadataGenerator metadataGenerator() {
        MetadataGenerator metadataGenerator = new MetadataGenerator()
        metadataGenerator.setEntityId("com:ttx:sp")
        metadataGenerator.setExtendedMetadata(extendedMetadata())
        metadataGenerator.setIncludeDiscoveryExtension(false)
        //metadataGenerator.setKeyManager(keyManager())
        return metadataGenerator
    }

    /*
    The filter is waiting for connections on URL suffixed with filterSuffix
    and presents SP metadata there

    筛选器正在等待带有后缀filterSuffix的URL上的连接，并在那里显示SP元数据
     */
    @Bean
    MetadataDisplayFilter metadataDisplayFilter() {
        return new MetadataDisplayFilter()
    }

    /*
     Handler deciding where to redirect user after successful login

     处理程序决定成功登录后将用户重定向到的位置
     */
    @Bean
    SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
        SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler = new SavedRequestAwareAuthenticationSuccessHandler()
        successRedirectHandler.setDefaultTargetUrl("/landing")
        return successRedirectHandler
    }

    /*
    Handler deciding where to redirect user after failed login

    处理程序决定登录失败后将用户重定向到何处
     */
    @Bean
    SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
        SimpleUrlAuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler()
        failureHandler.setUseForward(true)
        failureHandler.setDefaultFailureUrl("/error")
        return failureHandler
    }

    @Bean
    SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter() throws Exception {
        SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter = new SAMLWebSSOHoKProcessingFilter()
        samlWebSSOHoKProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler())
        samlWebSSOHoKProcessingFilter.setAuthenticationManager(authenticationManager())
        samlWebSSOHoKProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler())
        return samlWebSSOHoKProcessingFilter
    }

    /*
    Processing filter for WebSSO profile messages

    处理WebSSO配置文件消息的过滤器
     */
    @Bean
    SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
        SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter()
        samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager())
        samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler())
        samlWebSSOProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler())
        return samlWebSSOProcessingFilter
    }

    @Bean
    MetadataGeneratorFilter metadataGeneratorFilter() {
        return new MetadataGeneratorFilter(metadataGenerator())
    }

    /*
    Handler for successful logout

    成功注销的处理程序
     */
    @Bean
    SimpleUrlLogoutSuccessHandler successLogoutHandler() {
        SimpleUrlLogoutSuccessHandler successLogoutHandler = new SimpleUrlLogoutSuccessHandler()
        successLogoutHandler.setDefaultTargetUrl("/")
        return successLogoutHandler
    }

    /*
    Logout handler terminating local session

    注销处理程序终止本地会话
     */
    @Bean
    SecurityContextLogoutHandler logoutHandler() {
        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler()
        logoutHandler.setInvalidateHttpSession(true)
        logoutHandler.setClearAuthentication(true)
        return logoutHandler
    }

    /*
    Filter processing incoming logout messages
    First argument determines URL user will be redirected to after successful
    global logout

    过滤器处理传入的注销消息第一个参数确定成功注销全局用户后将URL用户重定向到
    */
    @Bean
    SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {
        return new SAMLLogoutProcessingFilter(successLogoutHandler(),
                logoutHandler())
    }

    /*
    Overrides default logout processing filter with the one processing SAML
    messages

    用一个处理SAML消息覆盖默认注销处理过滤器
    */
    @Bean
    SAMLLogoutFilter samlLogoutFilter() {
        LogoutHandler[] logoutHandler1 = [logoutHandler()]
        LogoutHandler[] logoutHandler2 = [logoutHandler()]
        return new SAMLLogoutFilter(successLogoutHandler(),
                logoutHandler1,
                logoutHandler2)
    }

    // Bindings
    private ArtifactResolutionProfile artifactResolutionProfile() {
        final ArtifactResolutionProfileImpl artifactResolutionProfile = new ArtifactResolutionProfileImpl(httpClient())
        artifactResolutionProfile.setProcessor(new SAMLProcessorImpl(soapBinding()))
        return artifactResolutionProfile
    }

    @Bean
    HTTPArtifactBinding artifactBinding(ParserPool parserPool, VelocityEngine velocityEngine) {
        return new HTTPArtifactBinding(parserPool, velocityEngine, artifactResolutionProfile())
    }

    @Bean
    HTTPSOAP11Binding soapBinding() {
        return new HTTPSOAP11Binding(parserPool())
    }

    @Bean
    HTTPPostBinding httpPostBinding() {
        return new HTTPPostBinding(parserPool(), velocityEngine())
    }

    @Bean
    HTTPRedirectDeflateBinding httpRedirectDeflateBinding() {
        return new HTTPRedirectDeflateBinding(parserPool())
    }

    @Bean
    HTTPSOAP11Binding httpSOAP11Binding() {
        return new HTTPSOAP11Binding(parserPool())
    }

    @Bean
    HTTPPAOS11Binding httpPAOS11Binding() {
        return new HTTPPAOS11Binding(parserPool())
    }

    // Processor
    @Bean
    SAMLProcessorImpl processor() {
        Collection<SAMLBinding> bindings = new ArrayList<SAMLBinding>()
        bindings.add(httpRedirectDeflateBinding())
        bindings.add(httpPostBinding())
        bindings.add(artifactBinding(parserPool(), velocityEngine()))
        bindings.add(httpSOAP11Binding())
        bindings.add(httpPAOS11Binding())
        return new SAMLProcessorImpl(bindings)
    }

    /**
     * Define the security filter chain in order to support SSO Auth by using SAML 2.0
     *
     * 定义安全筛选器链，以通过使用SAML 2.0支持SSO身份验证
     *
     * @return Filter chain proxy
     * @throws Exception
     */
    @Bean
    FilterChainProxy samlFilter() throws Exception {
        List<SecurityFilterChain> chains = new ArrayList<SecurityFilterChain>()
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/login/**"),
                samlEntryPoint()))
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/logout/**"),
                samlLogoutFilter()))
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/metadata/**"),
                metadataDisplayFilter()))
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSO/**"),
                samlWebSSOProcessingFilter()))
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSOHoK/**"),
                samlWebSSOHoKProcessingFilter()))
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SingleLogout/**"),
                samlLogoutProcessingFilter()))
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/discovery/**"),
                samlIDPDiscovery()))
        return new FilterChainProxy(chains)
    }

    /**
     Returns the authentication manager currently used by Spring.
     It represents a bean definition with the aim allow wiring from
     other classes performing the Inversion of Control (IoC).

     返回Spring当前使用的身份验证管理器。它代表一个bean定义，其目的是允许来自其他类的连线执行控制反转（IoC)
     *
     * @throws Exception
     */
    @Bean
    @Override
    AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean()
    }

    /**
     Defines the web based security configuration.
     定义基于Web的安全性配置
     * @param http It allows configuring web based security for specific http requests.
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .httpBasic()
                .authenticationEntryPoint(samlEntryPoint())
        http
                .addFilterBefore(metadataGeneratorFilter(), ChannelProcessingFilter.class)
                .addFilterAfter(samlFilter(), BasicAuthenticationFilter.class)
                .addFilterBefore(samlFilter(), CsrfFilter.class)
        http
                .authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/saml/**").permitAll()
                .antMatchers("/css/**").permitAll()
                .antMatchers("/img/**").permitAll()
                .antMatchers("/js/**").permitAll()
                .anyRequest().authenticated()
        http
                .logout()
                .disable()    // The logout procedure is already handled by SAML filters.
    }

    /**
     * Sets a custom authentication provider.
     * 设置自定义身份验证提供程序。
     *
     * @param auth SecurityBuilder used to create an AuthenticationManager.
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .authenticationProvider(samlAuthenticationProvider())
    }

    @Override
    void afterPropertiesSet() throws Exception {
        init()
    }

    @Override
    void destroy() throws Exception {
        shutdown()
    }

}
