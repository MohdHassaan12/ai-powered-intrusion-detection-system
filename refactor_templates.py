import os
import re

TEMPLATE_DIR = 'templates'
templates = ['home.html', 'monitoring.html', 'analyze.html', 'results.html', 'logs.html', 'settings.html']

for t in templates:
    filepath = os.path.join(TEMPLATE_DIR, t)
    if not os.path.exists(filepath): continue
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    # If already refactored, skip
    if "{% extends 'base.html' %}" in content: continue

    # Extract CSS/Head stuff
    head_match = re.search(r'<head>(.*?)</head>', content, re.DOTALL)
    head_content = head_match.group(1) if head_match else ""
    
    # We want to extract Leaflet CSS and Map scripts
    extra_head = ""
    if "leaflet" in head_content:
        extra_head += '<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />\n'
    
    # Extract Body content
    body_match = re.search(r'<body>(.*?)</body>', content, re.DOTALL)
    body_content = body_match.group(1) if body_match else ""

    # Remove Nav
    body_content = re.sub(r'<nav.*?</nav>', '', body_content, flags=re.DOTALL)
    # Remove footer
    body_content = re.sub(r'<footer.*?</footer>', '', body_content, flags=re.DOTALL)
    # Remove script tags that are bootstrap or theme toggle
    body_content = re.sub(r'<script src="https://cdn.jsdelivr.net/npm/bootstrap.*?</script>', '', body_content, flags=re.DOTALL)
    
    # Find active scripts inside body that we need to keep
    scripts = ""
    script_matches = re.finditer(r'(<script src="https://unpkg.com/leaflet.*?<script>.*?</script>)', body_content, re.DOTALL)
    for match in script_matches:
        scripts += match.group(1) + "\n"
        body_content = body_content.replace(match.group(1), '')
        
    other_script_matches = re.finditer(r'<script>.*?</script>', body_content, re.DOTALL)
    for match in other_script_matches:
        txt = match.group(0)
        if "function triggerSimulatedAttack" in txt or "trafficChart" in txt or "dropZone" in txt:
           scripts += txt + "\n"
           body_content = body_content.replace(txt, '')

    new_content = f"""{{% extends 'base.html' %}}

{{% block title %}}{t.replace('.html', '').capitalize()} - SOC{{% endblock %}}

{{% block head %}}
{extra_head}
{{% endblock %}}

{{% block content %}}
{body_content}
{{% endblock %}}

{{% block scripts %}}
{scripts}
{{% endblock %}}
"""
    with open(filepath, 'w') as f:
        f.write(new_content)

print("Templates refactored.")
