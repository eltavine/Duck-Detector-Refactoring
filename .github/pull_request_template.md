## Summary

<!-- What changed, and why? Keep this focused on the user-visible or detector-visible outcome. -->

- 
- 

## Change Type

<!-- Check all that apply. -->

- [ ] Feature / new detector capability
- [ ] Bug fix / false positive or false negative reduction
- [ ] Refactor with no intended behavior change
- [ ] UI / copy / localization
- [ ] Build / CI / release / versioning
- [ ] Documentation only

## Affected Areas

<!-- Check all touched risk areas. -->

- [ ] Kotlin data/domain/presentation logic
- [ ] Compose UI
- [ ] Native / JNI / C++
- [ ] SELinux / app_zygote / `/proc` / mount / cgroup behavior
- [ ] AndroidKeyStore / TEE / StrongBox / Binder behavior
- [ ] Zygisk / LSPosed / root-runtime probes
- [ ] Gradle / dependency / versioning / release workflow
- [ ] Notifications / Telegram / QQ / release publishing
- [ ] Strings / i18n / user-facing copy

## Detector Behavior Impact

<!-- Required for detector, reducer, mapper, native, or probe changes. -->

- New signals:
- Changed verdict / severity rules:
- Expected false-positive impact:
- Expected false-negative impact:
- Compatibility notes by Android version / ROM / device class:

## Architecture / Coupling Notes

<!-- Explain why touched modules need to change together. Especially important for native payload + Kotlin parser + reducer + UI changes. -->

- 

## Validation

<!-- Required: paste the exact commands run and the result. PRs should include real validation, not only code inspection. Mark anything not run as N/A with a reason. -->

- [ ] Compilation passed:
  - Command:
  - Result:
- [ ] Real test completed:
  - What was tested:
  - Result:
- [ ] Unit tests:
  - 
- [ ] `:app:assembleDebug`:
  - 
- [ ] Native build / JNI validation:
  - 
- [ ] Release / workflow validation, if build or CI changed:
  - 
- [ ] Manual app smoke test:
  - 

## Device / Runtime Testing

<!-- Required for TEE, KeyStore, Binder, SELinux, mount, cgroup, Zygisk, LSPosed, native, or root-runtime changes. -->

Tested on:

- Device / ROM / Android version:
- Root / module environment:
- Result:

Not tested on real device because:

- 

Optional comparison testing:

- [ ] Unlocked / rooted / modified device tested:
  - Device / ROM / Android version:
  - Root / module environment:
  - Result:
- [ ] Stock / normal device tested:
  - Device / ROM / Android version:
  - Result:
- [ ] Comparison testing not performed:
  - Reason:

## Documentation And Strings

- [ ] README / docs updated
- [ ] Strings updated where user-facing text changed
- [ ] No documentation or string update needed

Reason:

- 

## Revert / Rollback Plan

<!-- What is the smallest safe rollback if this causes crashes, false positives, broken builds, or release issues? -->

- 
