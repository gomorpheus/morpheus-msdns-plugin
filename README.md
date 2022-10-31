## Microsoft DNS Morpheus Plugin

This is the official Morpheus plugin for interacting with Microsoft DNS. This automates functions as it relates to automatically creating DNS Records and cleaning up DNS records both during workload provisioning and manual. It should be noted that if joining a VM to a Domain, this integration is not needed as the Domain joining typically auto creates a zone record. This was originally embedded into morpheus and is being extracted for easier maintenance

### Building

This is a Morpheus plugin that leverages the `morpheus-plugin-core` which can be referenced by visiting [https://developer.morpheusdata.com](https://developer.morpheusdata.com). It is a groovy plugin designed to be uploaded into a Morpheus environment via the `Administration -> Integrations -> Plugins` section. To build this product from scratch simply run the shadowJar gradle task on java 11:

```bash
./gradlew shadowJar
```

A jar will be produced in the `build/lib` folder that can be uploaded into a Morpheus environment.

### Configuring

Once the plugin is loaded in the environment. Microsoft DNS Becomes available in `Infrastructure -> Network -> Services`.

When adding the integration simply enter ip of the Microsoft DNS Server and the credentials with sufficient enough winrm privileges.

