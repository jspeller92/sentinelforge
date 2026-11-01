import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DETECTIONS_DIR = PROJECT_ROOT / "detections"
OUTPUT_DIR = PROJECT_ROOT / "output" / "splunk"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


failed_rules = []
successful_builds = 0
successful_builds_names = []

for rule in sorted(DETECTIONS_DIR.rglob("*.yml")):

    print(f"VALIDATING: {rule.name}")

    output_file = OUTPUT_DIR / f"{rule.stem}.spl"

    validation_command = [
        "sigma",
        "check",
        str(rule),
    ]

    validation_result = subprocess.run(
        validation_command,
        capture_output=True,
        text=True,
    )

    if validation_result.returncode != 0:
        print(f"VALIDATION FAILED: {rule.name}")
        print(validation_result.stdout)
        print(validation_result.stderr)
        
        failed_rules.append(rule.name)

        #remove any outdated ouput from a previous successful build.
        output_file.unlink(missing_ok=True)

        continue
    
    print(f"VALIDATION PASSED: {rule.name}")



    command = [
        "sigma",
        "convert",
        "-t", "splunk",
        "-p", "splunk_windows",
        str(rule),
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )

    successful_builds_names.append(rule.name)

    if result.returncode != 0:
        print(f"CONVERSION FAILED: {rule.name}")
        print(result.stdout)
        print(result.stderr)

        failed_rules.append(rule.name)
        output_file.unlink(missing_ok=True)

        continue
        
    
    output_file.write_text(result.stdout)

    print(f"BUILT: {output_file.name}")
    successful_builds += 1

print("\n========== BUILD SUMMARY ==========")
print(f"Successful builds: {successful_builds}")
print(f"Failed rules: {len(failed_rules)}")

if failed_rules:
    print("\nRules requiring attention:")

    for failed_rule in failed_rules:
        print(f"- {failed_rule}")

    

print("\nSUCCESSFUL BUILDS:")
for name in successful_builds_names:
    print(f"{name}")