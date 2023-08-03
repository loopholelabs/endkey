// Code generated by swaggo/swag. DO NOT EDIT.

package docs

import "github.com/swaggo/swag/v2"

const docTemplateapi = `{
    "schemes": {{ marshal .Schemes }},"consumes":["application/json"],"produces":["application/json"],"swagger":"2.0","info":{"description":"{{escape .Description}}","title":"{{.Title}}","termsOfService":"https://loopholelabs.io/privacy","contact":{"name":"API Support","email":"admin@loopholelabs.io"},"license":{"name":"Apache 2.0","url":"https://www.apache.org/licenses/LICENSE-2.0.html"},"version":"{{.Version}}"},"host":"{{.Host}}","basePath":"{{.BasePath}}","paths":{"/apikey":{"post":{"description":"Create a new API Key for a given Authority","consumes":["application/json"],"produces":["application/json"],"tags":["apikey"],"parameters":[{"description":"Create API Key Request","name":"request","in":"body","required":true,"schema":{"$ref":"#/definitions/models.CreateAPIKeyRequest"}}],"responses":{"200":{"description":"OK","schema":{"$ref":"#/definitions/models.APIKeyResponse"}},"400":{"description":"Bad Request","schema":{"type":"string"}},"401":{"description":"Unauthorized","schema":{"type":"string"}},"404":{"description":"Not Found","schema":{"type":"string"}},"409":{"description":"Conflict","schema":{"type":"string"}},"412":{"description":"Precondition Failed","schema":{"type":"string"}},"500":{"description":"Internal Server Error","schema":{"type":"string"}}}},"delete":{"description":"Delete an API Key","consumes":["application/json"],"produces":["application/json"],"tags":["apikey"],"parameters":[{"description":"Delete API Key Request","name":"request","in":"body","required":true,"schema":{"$ref":"#/definitions/models.DeleteAPIKeyRequest"}}],"responses":{"200":{"description":"OK","schema":{"type":"string"}},"400":{"description":"Bad Request","schema":{"type":"string"}},"401":{"description":"Unauthorized","schema":{"type":"string"}},"404":{"description":"Not Found","schema":{"type":"string"}},"409":{"description":"Conflict","schema":{"type":"string"}},"412":{"description":"Precondition Failed","schema":{"type":"string"}},"500":{"description":"Internal Server Error","schema":{"type":"string"}}}}},"/apikey/{authority_name}":{"get":{"description":"Lists all the api keys","consumes":["application/json"],"produces":["application/json"],"tags":["apikey"],"parameters":[{"type":"string","description":"Authority Name","name":"authority_name","in":"path","required":true}],"responses":{"200":{"description":"OK","schema":{"type":"array","items":{"$ref":"#/definitions/models.APIKeyResponse"}}},"400":{"description":"Bad Request","schema":{"type":"string"}},"401":{"description":"Unauthorized","schema":{"type":"string"}},"404":{"description":"Not Found","schema":{"type":"string"}},"409":{"description":"Conflict","schema":{"type":"string"}},"412":{"description":"Precondition Failed","schema":{"type":"string"}},"500":{"description":"Internal Server Error","schema":{"type":"string"}}}}},"/authority":{"get":{"description":"List authorities","consumes":["application/json"],"produces":["application/json"],"tags":["authority"],"responses":{"200":{"description":"OK","schema":{"type":"array","items":{"$ref":"#/definitions/models.AuthorityResponse"}}},"400":{"description":"Bad Request","schema":{"type":"string"}},"401":{"description":"Unauthorized","schema":{"type":"string"}},"404":{"description":"Not Found","schema":{"type":"string"}},"409":{"description":"Conflict","schema":{"type":"string"}},"412":{"description":"Precondition Failed","schema":{"type":"string"}},"500":{"description":"Internal Server Error","schema":{"type":"string"}}}},"post":{"description":"Create a new Authority","consumes":["application/json"],"produces":["application/json"],"tags":["authority"],"parameters":[{"description":"Create Authority Request","name":"request","in":"body","required":true,"schema":{"$ref":"#/definitions/models.CreateAuthorityRequest"}}],"responses":{"200":{"description":"OK","schema":{"$ref":"#/definitions/models.AuthorityResponse"}},"400":{"description":"Bad Request","schema":{"type":"string"}},"401":{"description":"Unauthorized","schema":{"type":"string"}},"404":{"description":"Not Found","schema":{"type":"string"}},"409":{"description":"Conflict","schema":{"type":"string"}},"412":{"description":"Precondition Failed","schema":{"type":"string"}},"500":{"description":"Internal Server Error","schema":{"type":"string"}}}}},"/authority/{name}":{"get":{"description":"Get an authority","consumes":["application/json"],"produces":["application/json"],"tags":["authority"],"parameters":[{"type":"string","description":"Authority Name","name":"name","in":"path","required":true}],"responses":{"200":{"description":"OK","schema":{"$ref":"#/definitions/models.AuthorityResponse"}},"400":{"description":"Bad Request","schema":{"type":"string"}},"401":{"description":"Unauthorized","schema":{"type":"string"}},"404":{"description":"Not Found","schema":{"type":"string"}},"409":{"description":"Conflict","schema":{"type":"string"}},"412":{"description":"Precondition Failed","schema":{"type":"string"}},"500":{"description":"Internal Server Error","schema":{"type":"string"}}}},"delete":{"description":"Delete an authority","consumes":["application/json"],"produces":["application/json"],"tags":["authority"],"parameters":[{"type":"string","description":"Authority Name","name":"name","in":"path","required":true}],"responses":{"200":{"description":"OK","schema":{"type":"string"}},"400":{"description":"Bad Request","schema":{"type":"string"}},"401":{"description":"Unauthorized","schema":{"type":"string"}},"404":{"description":"Not Found","schema":{"type":"string"}},"409":{"description":"Conflict","schema":{"type":"string"}},"412":{"description":"Precondition Failed","schema":{"type":"string"}},"500":{"description":"Internal Server Error","schema":{"type":"string"}}}}},"/certificate":{"get":{"description":"Retrieves the CA Certificate","consumes":["application/json"],"produces":["application/json"],"tags":["certificate"],"responses":{"200":{"description":"OK","schema":{"$ref":"#/definitions/models.CAResponse"}},"400":{"description":"Bad Request","schema":{"type":"string"}},"401":{"description":"Unauthorized","schema":{"type":"string"}},"404":{"description":"Not Found","schema":{"type":"string"}},"409":{"description":"Conflict","schema":{"type":"string"}},"412":{"description":"Precondition Failed","schema":{"type":"string"}},"500":{"description":"Internal Server Error","schema":{"type":"string"}}}},"post":{"description":"Create a new Certificate","consumes":["application/json"],"produces":["application/json"],"tags":["certificate"],"parameters":[{"description":"Create Certificate Request","name":"request","in":"body","required":true,"schema":{"$ref":"#/definitions/models.CreateCertificateRequest"}}],"responses":{"200":{"description":"OK","schema":{"$ref":"#/definitions/models.CertificateResponse"}},"400":{"description":"Bad Request","schema":{"type":"string"}},"401":{"description":"Unauthorized","schema":{"type":"string"}},"404":{"description":"Not Found","schema":{"type":"string"}},"409":{"description":"Conflict","schema":{"type":"string"}},"412":{"description":"Precondition Failed","schema":{"type":"string"}},"500":{"description":"Internal Server Error","schema":{"type":"string"}}}}},"/health":{"get":{"description":"Returns the health and status of the various services that make up the API.","consumes":["application/json"],"produces":["application/json"],"tags":["health"],"responses":{"200":{"description":"OK","schema":{"$ref":"#/definitions/models.HealthResponse"}},"500":{"description":"Internal Server Error","schema":{"type":"string"}}}}},"/rootkey":{"get":{"description":"Lists all the root keys","consumes":["application/json"],"produces":["application/json"],"tags":["rootkey"],"responses":{"200":{"description":"OK","schema":{"type":"array","items":{"$ref":"#/definitions/models.RootKeyResponse"}}},"400":{"description":"Bad Request","schema":{"type":"string"}},"401":{"description":"Unauthorized","schema":{"type":"string"}},"404":{"description":"Not Found","schema":{"type":"string"}},"409":{"description":"Conflict","schema":{"type":"string"}},"412":{"description":"Precondition Failed","schema":{"type":"string"}},"500":{"description":"Internal Server Error","schema":{"type":"string"}}}}},"/rootkey/rotate/{name}":{"post":{"description":"Rotates a given Root Key","consumes":["application/json"],"produces":["application/json"],"tags":["rootkey"],"parameters":[{"type":"string","description":"Root Key Name","name":"name","in":"path","required":true}],"responses":{"200":{"description":"OK","schema":{"$ref":"#/definitions/models.RootKeyResponse"}},"400":{"description":"Bad Request","schema":{"type":"string"}},"401":{"description":"Unauthorized","schema":{"type":"string"}},"404":{"description":"Not Found","schema":{"type":"string"}},"409":{"description":"Conflict","schema":{"type":"string"}},"412":{"description":"Precondition Failed","schema":{"type":"string"}},"500":{"description":"Internal Server Error","schema":{"type":"string"}}}}},"/rootkey/{name}":{"post":{"description":"Create a new Root Key","consumes":["application/json"],"produces":["application/json"],"tags":["rootkey"],"parameters":[{"type":"string","description":"Root Key Name","name":"name","in":"path","required":true}],"responses":{"200":{"description":"OK","schema":{"$ref":"#/definitions/models.RootKeyResponse"}},"400":{"description":"Bad Request","schema":{"type":"string"}},"401":{"description":"Unauthorized","schema":{"type":"string"}},"404":{"description":"Not Found","schema":{"type":"string"}},"409":{"description":"Conflict","schema":{"type":"string"}},"412":{"description":"Precondition Failed","schema":{"type":"string"}},"500":{"description":"Internal Server Error","schema":{"type":"string"}}}},"delete":{"description":"Delete a Root Key","consumes":["application/json"],"produces":["application/json"],"tags":["rootkey"],"parameters":[{"type":"string","description":"Root Key Name","name":"name","in":"path","required":true}],"responses":{"200":{"description":"OK","schema":{"type":"string"}},"400":{"description":"Bad Request","schema":{"type":"string"}},"401":{"description":"Unauthorized","schema":{"type":"string"}},"404":{"description":"Not Found","schema":{"type":"string"}},"409":{"description":"Conflict","schema":{"type":"string"}},"412":{"description":"Precondition Failed","schema":{"type":"string"}},"500":{"description":"Internal Server Error","schema":{"type":"string"}}}}},"/template/client":{"post":{"description":"Create a new Client Template","consumes":["application/json"],"produces":["application/json"],"tags":["template"],"parameters":[{"description":"Create Client Template Request","name":"request","in":"body","required":true,"schema":{"$ref":"#/definitions/models.CreateClientTemplateRequest"}}],"responses":{"200":{"description":"OK","schema":{"$ref":"#/definitions/models.ClientTemplateResponse"}},"400":{"description":"Bad Request","schema":{"type":"string"}},"401":{"description":"Unauthorized","schema":{"type":"string"}},"404":{"description":"Not Found","schema":{"type":"string"}},"409":{"description":"Conflict","schema":{"type":"string"}},"412":{"description":"Precondition Failed","schema":{"type":"string"}},"500":{"description":"Internal Server Error","schema":{"type":"string"}}}},"delete":{"description":"Delete a Client Template","consumes":["application/json"],"produces":["application/json"],"tags":["template"],"parameters":[{"description":"Delete Client Template Request","name":"request","in":"body","required":true,"schema":{"$ref":"#/definitions/models.DeleteClientTemplateRequest"}}],"responses":{"200":{"description":"OK","schema":{"type":"string"}},"400":{"description":"Bad Request","schema":{"type":"string"}},"401":{"description":"Unauthorized","schema":{"type":"string"}},"404":{"description":"Not Found","schema":{"type":"string"}},"409":{"description":"Conflict","schema":{"type":"string"}},"412":{"description":"Precondition Failed","schema":{"type":"string"}},"500":{"description":"Internal Server Error","schema":{"type":"string"}}}}},"/template/client/{authority_name}":{"get":{"description":"List all Client Templates","consumes":["application/json"],"produces":["application/json"],"tags":["template"],"parameters":[{"type":"string","description":"Authority Name","name":"authority_name","in":"path","required":true}],"responses":{"200":{"description":"OK","schema":{"type":"array","items":{"$ref":"#/definitions/models.ClientTemplateResponse"}}},"400":{"description":"Bad Request","schema":{"type":"string"}},"401":{"description":"Unauthorized","schema":{"type":"string"}},"404":{"description":"Not Found","schema":{"type":"string"}},"409":{"description":"Conflict","schema":{"type":"string"}},"412":{"description":"Precondition Failed","schema":{"type":"string"}},"500":{"description":"Internal Server Error","schema":{"type":"string"}}}}},"/template/server":{"post":{"description":"Create a new Server Template","consumes":["application/json"],"produces":["application/json"],"tags":["template"],"parameters":[{"description":"Create Server Template Request","name":"request","in":"body","required":true,"schema":{"$ref":"#/definitions/models.CreateServerTemplateRequest"}}],"responses":{"200":{"description":"OK","schema":{"$ref":"#/definitions/models.ServerTemplateResponse"}},"400":{"description":"Bad Request","schema":{"type":"string"}},"401":{"description":"Unauthorized","schema":{"type":"string"}},"404":{"description":"Not Found","schema":{"type":"string"}},"409":{"description":"Conflict","schema":{"type":"string"}},"412":{"description":"Precondition Failed","schema":{"type":"string"}},"500":{"description":"Internal Server Error","schema":{"type":"string"}}}},"delete":{"description":"Delete a Server Template","consumes":["application/json"],"produces":["application/json"],"tags":["template"],"parameters":[{"description":"Delete Server Template Request","name":"request","in":"body","required":true,"schema":{"$ref":"#/definitions/models.DeleteServerTemplateRequest"}}],"responses":{"200":{"description":"OK","schema":{"type":"string"}},"400":{"description":"Bad Request","schema":{"type":"string"}},"401":{"description":"Unauthorized","schema":{"type":"string"}},"404":{"description":"Not Found","schema":{"type":"string"}},"409":{"description":"Conflict","schema":{"type":"string"}},"412":{"description":"Precondition Failed","schema":{"type":"string"}},"500":{"description":"Internal Server Error","schema":{"type":"string"}}}}},"/template/server/{authority_name}":{"get":{"description":"List all Server Templates","consumes":["application/json"],"produces":["application/json"],"tags":["template"],"parameters":[{"type":"string","description":"Authority Name","name":"authority_name","in":"path","required":true}],"responses":{"200":{"description":"OK","schema":{"type":"array","items":{"$ref":"#/definitions/models.ServerTemplateResponse"}}},"400":{"description":"Bad Request","schema":{"type":"string"}},"401":{"description":"Unauthorized","schema":{"type":"string"}},"404":{"description":"Not Found","schema":{"type":"string"}},"409":{"description":"Conflict","schema":{"type":"string"}},"412":{"description":"Precondition Failed","schema":{"type":"string"}},"500":{"description":"Internal Server Error","schema":{"type":"string"}}}}},"/userkey":{"get":{"description":"Lists all the User Keys","consumes":["application/json"],"produces":["application/json"],"tags":["userkey"],"responses":{"200":{"description":"OK","schema":{"type":"array","items":{"$ref":"#/definitions/models.UserKeyResponse"}}},"400":{"description":"Bad Request","schema":{"type":"string"}},"401":{"description":"Unauthorized","schema":{"type":"string"}},"404":{"description":"Not Found","schema":{"type":"string"}},"409":{"description":"Conflict","schema":{"type":"string"}},"412":{"description":"Precondition Failed","schema":{"type":"string"}},"500":{"description":"Internal Server Error","schema":{"type":"string"}}}}},"/userkey/rotate/{name}":{"post":{"description":"Rotates a given User Key","consumes":["application/json"],"produces":["application/json"],"tags":["userkey"],"parameters":[{"type":"string","description":"User Key Name","name":"name","in":"path","required":true}],"responses":{"200":{"description":"OK","schema":{"$ref":"#/definitions/models.UserKeyResponse"}},"400":{"description":"Bad Request","schema":{"type":"string"}},"401":{"description":"Unauthorized","schema":{"type":"string"}},"404":{"description":"Not Found","schema":{"type":"string"}},"409":{"description":"Conflict","schema":{"type":"string"}},"412":{"description":"Precondition Failed","schema":{"type":"string"}},"500":{"description":"Internal Server Error","schema":{"type":"string"}}}}},"/userkey/{name}":{"post":{"description":"Create a new User Key","consumes":["application/json"],"produces":["application/json"],"tags":["userkey"],"parameters":[{"type":"string","description":"User Key Name","name":"name","in":"path","required":true}],"responses":{"200":{"description":"OK","schema":{"$ref":"#/definitions/models.UserKeyResponse"}},"400":{"description":"Bad Request","schema":{"type":"string"}},"401":{"description":"Unauthorized","schema":{"type":"string"}},"404":{"description":"Not Found","schema":{"type":"string"}},"409":{"description":"Conflict","schema":{"type":"string"}},"412":{"description":"Precondition Failed","schema":{"type":"string"}},"500":{"description":"Internal Server Error","schema":{"type":"string"}}}},"delete":{"description":"Delete a User Key","consumes":["application/json"],"produces":["application/json"],"tags":["userkey"],"parameters":[{"type":"string","description":"User Key Name","name":"name","in":"path","required":true}],"responses":{"200":{"description":"OK","schema":{"type":"string"}},"400":{"description":"Bad Request","schema":{"type":"string"}},"401":{"description":"Unauthorized","schema":{"type":"string"}},"404":{"description":"Not Found","schema":{"type":"string"}},"409":{"description":"Conflict","schema":{"type":"string"}},"412":{"description":"Precondition Failed","schema":{"type":"string"}},"500":{"description":"Internal Server Error","schema":{"type":"string"}}}}}},"definitions":{"models.APIKeyResponse":{"type":"object","properties":{"authority_name":{"type":"string"},"created_at":{"type":"string"},"id":{"type":"string"},"name":{"type":"string"},"secret":{"type":"string"},"template_kind":{"type":"string"},"template_name":{"type":"string"}}},"models.AuthorityResponse":{"type":"object","properties":{"ca_certificate":{"type":"string","format":"base64"},"common_name":{"type":"string"},"created_at":{"type":"string"},"expiry":{"type":"string"},"id":{"type":"string"},"name":{"type":"string"},"tag":{"type":"string"}}},"models.CAResponse":{"type":"object","properties":{"authority_name":{"type":"string"},"ca_certificate":{"type":"string","format":"base64"}}},"models.CertificateResponse":{"type":"object","properties":{"additional_dns_names":{"type":"array","items":{"type":"string"}},"additional_ip_addresses":{"type":"array","items":{"type":"string"}},"authority_name":{"type":"string"},"ca_certificate":{"type":"string","format":"base64"},"expiry":{"type":"string"},"public_certificate":{"type":"string","format":"base64"},"template_kind":{"type":"string"},"template_name":{"type":"string"}}},"models.ClientTemplateResponse":{"type":"object","properties":{"allow_additional_dns_names":{"type":"boolean"},"allow_additional_ips":{"type":"boolean"},"authority_name":{"type":"string"},"common_name":{"type":"string"},"created_at":{"type":"string"},"dns_names":{"type":"array","items":{"type":"string"}},"id":{"type":"string"},"ip_addresses":{"type":"array","items":{"type":"string"}},"name":{"type":"string"},"tag":{"type":"string"},"validity":{"type":"string"}}},"models.CreateAPIKeyRequest":{"type":"object","properties":{"authority_name":{"type":"string"},"name":{"type":"string"},"template_kind":{"type":"string"},"template_name":{"type":"string"}}},"models.CreateAuthorityRequest":{"type":"object","properties":{"common_name":{"type":"string"},"name":{"type":"string"},"tag":{"type":"string"},"validity":{"type":"string"}}},"models.CreateCertificateRequest":{"type":"object","properties":{"additional_dns_names":{"type":"array","items":{"type":"string"}},"additional_ip_addresses":{"type":"array","items":{"type":"string"}},"csr":{"type":"string","format":"base64"}}},"models.CreateClientTemplateRequest":{"type":"object","properties":{"allow_additional_dns_names":{"type":"boolean"},"allow_additional_ips":{"type":"boolean"},"authority_name":{"type":"string"},"common_name":{"type":"string"},"dns_names":{"type":"array","items":{"type":"string"}},"ip_addresses":{"type":"array","items":{"type":"string"}},"name":{"type":"string"},"tag":{"type":"string"},"validity":{"type":"string"}}},"models.CreateServerTemplateRequest":{"type":"object","properties":{"allow_additional_dns_names":{"type":"boolean"},"allow_additional_ips":{"type":"boolean"},"authority_name":{"type":"string"},"common_name":{"type":"string"},"dns_names":{"type":"array","items":{"type":"string"}},"ip_addresses":{"type":"array","items":{"type":"string"}},"name":{"type":"string"},"tag":{"type":"string"},"validity":{"type":"string"}}},"models.DeleteAPIKeyRequest":{"type":"object","properties":{"authority_name":{"type":"string"},"name":{"type":"string"}}},"models.DeleteClientTemplateRequest":{"type":"object","properties":{"authority_name":{"type":"string"},"name":{"type":"string"}}},"models.DeleteServerTemplateRequest":{"type":"object","properties":{"authority_name":{"type":"string"},"name":{"type":"string"}}},"models.HealthResponse":{"type":"object","properties":{"database":{"type":"boolean"}}},"models.RootKeyResponse":{"type":"object","properties":{"created_at":{"type":"string"},"id":{"type":"string"},"name":{"type":"string"},"secret":{"type":"string"}}},"models.ServerTemplateResponse":{"type":"object","properties":{"allow_additional_dns_names":{"type":"boolean"},"allow_additional_ips":{"type":"boolean"},"authority_name":{"type":"string"},"common_name":{"type":"string"},"created_at":{"type":"string"},"dns_names":{"type":"array","items":{"type":"string"}},"id":{"type":"string"},"ip_addresses":{"type":"array","items":{"type":"string"}},"name":{"type":"string"},"tag":{"type":"string"},"validity":{"type":"string"}}},"models.UserKeyResponse":{"type":"object","properties":{"created_at":{"type":"string"},"id":{"type":"string"},"name":{"type":"string"},"secret":{"type":"string"}}}}}`

// SwaggerInfoapi holds exported Swagger Info so clients can modify it
var SwaggerInfoapi = &swag.Spec{
	Version:          "1.0",
	Host:             "localhost:8080",
	BasePath:         "/v1",
	Schemes:          []string{"https"},
	Title:            "EndKey API V1",
	Description:      "Returns the health and status of the various services that make up the API.",
	InfoInstanceName: "api",
	SwaggerTemplate:  docTemplateapi,
	LeftDelim:        "{{",
	RightDelim:       "}}",
}

func init() {
	swag.Register(SwaggerInfoapi.InstanceName(), SwaggerInfoapi)
}
