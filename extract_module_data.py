#!/usr/bin/env python3
"""
Extract module names and their icons from stuff.txt
"""

def extract_module_data():
    """Extract all module names and their icons from stuff.txt"""
    
    module_data = []
    current_module = None
    
    with open('stuff.txt', 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            
            # Check for module header: [number/228] ""Module Name"" (Level X, Rarity)
            if line.startswith('[') and '/228]' in line and '""' in line:
                # Extract module number
                number_match = line.split('/')[0].replace('[', '')
                number = int(number_match)
                
                # Extract module name (between double quotes)
                name_start = line.find('""') + 2
                name_end = line.find('""', name_start)
                name = line[name_start:name_end]
                
                # Extract rarity
                rarity_start = line.find('Level') + 6
                rarity_end = line.find(')', rarity_start)
                if rarity_end == -1:
                    rarity_end = line.find(' -', rarity_start)
                if rarity_end == -1:
                    rarity_end = len(line)
                rarity = line[rarity_start:rarity_end].strip()
                
                current_module = {
                    'number': number,
                    'name': name,
                    'rarity': rarity,
                    'frame': None,
                    'icon': None
                }
            
            # Check for sprites line
            elif line.startswith('Sprites -> Frame:') and current_module:
                # Extract frame and icon (remove double quotes)
                frame_start = line.find('"') + 1
                frame_end = line.find('"', frame_start)
                frame = line[frame_start:frame_end]
                
                icon_start = line.find('"', frame_end + 1) + 1
                icon_end = line.find('"', icon_start)
                icon = line[icon_start:icon_end]
                
                current_module['frame'] = frame
                current_module['icon'] = icon
                
                # Add to module data
                module_data.append(current_module)
                current_module = None
    
    return module_data

def generate_lookup_dict(module_data):
    """Generate a lookup dictionary from module name to icon"""
    lookup = {}
    for module in module_data:
        lookup[module['name']] = module['icon']
    return lookup

def main():
    print("Extracting module data from stuff.txt...")
    module_data = extract_module_data()
    
    print(f"Found {len(module_data)} modules")
    
    # Generate lookup dictionary
    lookup = generate_lookup_dict(module_data)
    
    print("\nModule name to icon mapping:")
    print("MODULE_TO_ICON = {")
    for name, icon in sorted(lookup.items()):
        print(f'    "{name}": "{icon}",')
    print("}")
    
    # Count unique icons
    unique_icons = set(lookup.values())
    print(f"\nUnique icons found: {len(unique_icons)}")
    print("Unique icons:")
    for icon in sorted(unique_icons):
        print(f"  {icon}")
    
    # Find modules that use each icon
    icon_usage = {}
    for name, icon in lookup.items():
        if icon not in icon_usage:
            icon_usage[icon] = []
        icon_usage[icon].append(name)
    
    print(f"\nIcon usage breakdown:")
    for icon, modules in sorted(icon_usage.items()):
        print(f"  {icon}: {len(modules)} modules")
        if len(modules) > 1:
            print(f"    Used by: {', '.join(modules)}")

if __name__ == "__main__":
    main() 