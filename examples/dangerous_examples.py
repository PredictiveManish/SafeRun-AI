# Dangerous example - should be blocked
import os

os.system("rm -rf /important_data")
print("This should not execute")