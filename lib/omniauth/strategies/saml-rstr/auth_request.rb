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
                "<saml:Issuer>#{settings[:issuer]}</saml:Issuer>\n" +
                "<samlp:NameIDPolicy Format=\"#{settings[:name_identifier_format]}\" AllowCreate=\"true\"/>\n" +
                "<samlp:RequestedAuthnContext Comparison=\"exact\">" +
                    "<saml:AuthnContextClassRef>
                        urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
                    </saml:AuthnContextClassRef>
                </samlp:RequestedAuthnContext>\n" +
            "</samlp:AuthnRequest>"

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
