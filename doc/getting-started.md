# Getting Started

## Add to your West workspace

Add this repository as a project in your West manifest and register
west-commands.yml:

```yaml
manifest:
  projects:
    - name: zephyr-west-vulnscout
      url: https://github.com/ValentinBoudevinSFL/zephyr-west-vulnscout
      revision: main
      path: zephyr-west-vulnscout
      west-commands: west-commands.yml
```

Then update and verify command availability:

```sh
west update zephyr-west-vulnscout
west help vulnscout
```
