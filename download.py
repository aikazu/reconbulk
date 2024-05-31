import os
import requests
import subprocess

def download_tool(url, dest_folder):
    os.makedirs(dest_folder, exist_ok=True)
    local_filename = url.split('/')[-1]
    file_path = os.path.join(dest_folder, local_filename)

    if not os.path.exists(file_path):
        response = requests.get(url, stream=True)
        response.raise_for_status()  # Ensure we handle download errors
        with open(file_path, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)
        os.chmod(file_path, 0o755)
    else:
        print(f"{local_filename} already exists in {dest_folder}")

def get_latest_release_download_url(repo, asset_name_substring):
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    response = requests.get(url)
    response.raise_for_status()
    assets = response.json().get('assets', [])
    for asset in assets:
        print(f"Checking asset: {asset['name']}")  # Debug line
        if asset_name_substring in asset['name'] and 'i386' not in asset['name']:
            return asset['browser_download_url']
    raise Exception(f"No asset found for {asset_name_substring} in the latest release of {repo}")

def clone_massdns(dest_folder):
    os.makedirs(dest_folder, exist_ok=True)
    repo_url = "https://github.com/blechschmidt/massdns.git"
    subprocess.run(["git", "clone", repo_url, os.path.join(dest_folder, "massdns")], check=True)

def main():
    tools = [
        {
            "name": "amass",
            "url": "https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_amd64.zip"
        },
        {
            "name": "subfinder",
            "repo": "projectdiscovery/subfinder",
            "asset_name_substring": "linux_amd64"
        },
        {
            "name": "assetfinder",
            "url": "https://github.com/tomnomnom/assetfinder/releases/download/v0.1.1/assetfinder-linux-amd64-0.1.1.tgz"
        },
        {
            "name": "findomain",
            "repo": "Findomain/Findomain",
            "asset_name_substring": "findomain-linux"
        },
        {
            "name": "massdns",
            "special_case": True
        },
        {
            "name": "httpx",
            "repo": "projectdiscovery/httpx",
            "asset_name_substring": "linux_amd64"
        },
        {
            "name": "naabu",
            "repo": "projectdiscovery/naabu",
            "asset_name_substring": "linux_amd64"
        },
        {
            "name": "nuclei",
            "repo": "projectdiscovery/nuclei",
            "asset_name_substring": "linux_amd64"
        }
    ]

    tools_dir = "tools"
    os.makedirs(tools_dir, exist_ok=True)

    massdns_downloaded = False

    for tool in tools:
        try:
            if tool.get("special_case"):
                if tool["name"] == "massdns":
                    print(f"Cloning {tool['name']}...")
                    clone_massdns(tools_dir)
                    massdns_downloaded = True
            elif "url" in tool:
                print(f"Downloading {tool['name']} from provided URL...")
                download_tool(tool["url"], tools_dir)
            else:
                print(f"Downloading {tool['name']} from GitHub...")
                download_url = get_latest_release_download_url(tool["repo"], tool["asset_name_substring"])
                download_tool(download_url, tools_dir)
        except Exception as e:
            print(f"Failed to download {tool['name']}: {e}")

    print("All tools are downloaded successfully.")

    if massdns_downloaded:
        print("\nMassDNS requires manual compilation. Please run the following commands:")
        print(f"cd {os.path.join(tools_dir, 'massdns')}")
        print("make")
        print(f"mv bin/massdns ../tools/")

if __name__ == "__main__":
    main()
