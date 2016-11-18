require "base64"
require "uuid"
require "zlib"
require "cgi"

module OmniAuth
  module Strategies
    class SAML_RSTR
      class AuthRequest

        def create(settings, params = {})
          uuid = "_" + UUID.new.generate
          time = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")

          request =
            "<samlp:AuthnRequest
                                  Destination=\"#{settings[:idp_sso_target_url]}\"
                                  Version='2.0'
                                  ID=\"#{uuid}\"
                                  IssueInstant=\"#{time}\"
                                  ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"
                                  AssertionConsumerServiceURL=\"#{settings[:assertion_consumer_service_url]}\"
                                  xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'
                                  xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol'>"+
                "<saml:Issuer>#{settings[:issuer]}</saml:Issuer>" +
                "<samlp:NameIDPolicy Format=\"#{settings[:name_identifier_format]}\" AllowCreate=\"true\"/>" +
                "<samlp:RequestedAuthnContext Comparison=\"exact\">" +
                    "<saml:AuthnContextClassRef>
                        urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
                    </saml:AuthnContextClassRef>
                </samlp:RequestedAuthnContext>" +
            "</samlp:AuthnRequest>"

            "<samlp:AuthnRequest AssertionConsumerServiceURL='https://developer.earthdata.nasa.gov/saml/acs'
                                 Destination='https://auth.launchpad-sbx.nasa.gov/affwebservices/public/saml2sso'
                                 ID='_c8122219-636c-4d7b-9fe5-0b5e6be4f930'
                                 IssueInstant='2016-11-17T20:34:07Z'
                                 ProtocolBinding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
                                 Version='2.0'
                                 xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'
                                 xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol'>
             <saml:Issuer>https://developer.earthdata.nasa.gov/saml/acs</saml:Issuer>
             <samlp:NameIDPolicy AllowCreate='true' Format='urn:oasis:names:tc:SAML:2.0:nameid-format:transient'/>
             <samlp:RequestedAuthnContext Comparison='exact'>
                <saml:AuthnContextClassRef>
                      urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
                </saml:AuthnContextClassRef>
              </samlp:RequestedAuthnContext>
            </samlp:AuthnRequest>"

          deflated_request  = Zlib::Deflate.deflate(request, 9)[2..-5]
          base64_request    = Base64.encode64(deflated_request)
          encoded_request   = CGI.escape(base64_request)
          request_params    = "?SAMLRequest=" + encoded_request

          params.each_pair do |key, value|
            request_params << "&#{key}=#{CGI.escape(value.to_s)}"
          end

          settings[:idp_sso_target_url] + request_params
        end

      end
    end
  end
end
