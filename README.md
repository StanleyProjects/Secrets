# Secrets
Classes for working with encryption.

---

## Snapshot

> GitHub [0.0.1-SNAPSHOT](https://github.com/StanleyProjects/Secrets/releases/tag/0.0.1-SNAPSHOT) release
>
> Maven [metadata](https://central.sonatype.com/repository/maven-snapshots/com/github/kepocnhh/Secrets/maven-metadata.xml)

### Build
```
$ gradle lib:assembleSnapshotJar
```

### Import
```kotlin
repositories {
    maven("https://central.sonatype.com/repository/maven-snapshots")
}

dependencies {
    implementation("com.github.kepocnhh:Secrets:0.0.1-SNAPSHOT")
}
```

---

## Unstable

> GitHub [0.0.1u-SNAPSHOT](https://github.com/StanleyProjects/Secrets/releases/tag/0.0.1u-SNAPSHOT) release
>
> Maven [metadata](https://central.sonatype.com/repository/maven-snapshots/com/github/kepocnhh/Secrets/maven-metadata.xml)

### Build
```
$ gradle lib:assembleUnstableJar
```

### Import
```kotlin
repositories {
    maven("https://central.sonatype.com/repository/maven-snapshots")
}

dependencies {
    implementation("com.github.kepocnhh:Secrets:0.0.1u-SNAPSHOT")
}
```

---
