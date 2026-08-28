rootProject.name = "kerosene-shared"

val contractsDirectory = providers.environmentVariable("KEROSENE_CONTRACTS_DIR")
    .orElse("../kerosene-contracts")
    .get()

includeBuild(contractsDirectory) {
    dependencySubstitution {
        substitute(module("io.kerosene.contracts:kerosene-contracts"))
            .using(project(":"))
    }
}
