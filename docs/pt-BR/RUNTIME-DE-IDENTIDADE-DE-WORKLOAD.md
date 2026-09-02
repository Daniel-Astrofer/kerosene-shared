# Runtime de identidade SPIFFE

O pacote `com.kerosene.common.security.workload` contém somente a camada Java
de transporte reutilizada por Auth e KFE. Rotas, regras de autorização e
manifests de deploy continuam pertencendo a cada serviço.

Quando habilitado, o runtime acessa a Workload API por socket Unix, aguarda o
X.509-SVID e o bundle de confiança e recusa a inicialização se o SPIFFE ID
emitido não for exatamente o ID configurado para o processo. Os contextos TLS
1.3 de cliente e servidor aceitam exatamente um SPIFFE ID de par; não existe
modo `acceptAny`. Certificados, bundles e chaves rotacionam em memória, sem
gravar a chave privada em arquivo.

Cada serviço deve abrir uma porta HTTPS interna separada e escolher seus
próprios prefixos protegidos no `InternalServiceAuthenticationFilter`. A porta
pública não passa pela validação de porta interna. O modo com segredo
compartilhado existe apenas para compatibilidade local explícita e falha fechado
se o segredo estiver ausente. Em produção, o gate do serviço deve exigir
identidade de workload e proibir esse segredo legado.

A biblioteca não torna o cluster seguro sozinha. Produção ainda exige
registros SPIRE corretos, isolamento do socket da Workload API, NetworkPolicy,
imagens imutáveis e teste real de handshake no cluster de destino.
