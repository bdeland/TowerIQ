import structlog
import yaml
import random
import colorama
from typing import Dict, List, Set, Optional, Tuple, Any
import datetime

lookup_file = "resources/lookups/module_lookups.yaml"

# Initialize logger
logger = structlog.get_logger()

def build_module_lookup(lookup_file: str):
    try:
        with open(lookup_file, "r") as f:
            module_lookups = yaml.safe_load(f)
        logger.info("Module lookup data loaded successfully", file=lookup_file)
        return module_lookups
    except FileNotFoundError:
        logger.error("Module lookup file not found", file=lookup_file)
        raise
    except yaml.YAMLError as e:
        logger.error("Failed to parse YAML file", file=lookup_file, error=str(e))
        raise
    except Exception as e:
        logger.error("Unexpected error loading module lookup", file=lookup_file, error=str(e))
        raise

module_lookups = build_module_lookup(lookup_file)

def get_substat_value(enum_id, rarity):
    try:
        return module_lookups['substat_values'][enum_id]['values'][rarity]
    except KeyError:
        logger.error("Substat value not found", enum_id=enum_id, rarity=rarity)
        return None

def get_substat_name(enum_id):
    try:
        return module_lookups['substat_values'][enum_id]['name'].replace('_', ' ')
    except KeyError:
        logger.error("Substat name not found", enum_id=enum_id)
        return None

def get_substat_unit(enum_id):
    try:
        return module_lookups['substat_values'][enum_id]['unit']
    except KeyError:
        logger.error("Substat unit not found", enum_id=enum_id)
        return None
    
def get_substat_value_sign(enum_id, rarity):
    try:
        if module_lookups['substat_values'][enum_id]['values'][rarity] > 0:
            return "+"
        else:
            return ""
    except KeyError:
        logger.error("Substat value sign not found", enum_id=enum_id, rarity=rarity)
        return None

def get_substat_value_formatted(enum_id, rarity):
    substat_value_sign = get_substat_value_sign(enum_id, rarity)
    substat_value = get_substat_value(enum_id, rarity)
    substat_unit = get_substat_unit(enum_id)
    return f"{substat_value_sign}{substat_value}{substat_unit}"

def get_substat_light_color(rarity):
    try:
        return module_lookups['rarity_colors'][rarity]['light_color']
    except KeyError:
        return None

def get_substat_dark_color(rarity):
    try:
        return module_lookups['rarity_colors'][rarity]['dark_color']
    except KeyError:
        return None

def hex_to_rgb(hex_str):
    hex_str = hex_str.strip("#")
    return tuple(int(hex_str[i:i+2], 16) for i in (0, 2, 4))

def print_colored(text, hex_color, background=False):
    r, g, b = hex_to_rgb(hex_color)
    prefix = "48" if background else "38"
    return (f"\033[{prefix};2;{r};{g};{b}m{text}\033[0m")

def validate(enum_id, rarity, module_type: Optional[str] = None, module_id: Optional[int] = None) -> Dict[str, Any]:
    """
    Comprehensive validation function for module combinations.
    
    Args:
        enum_id: The substat enum ID to validate
        rarity: The rarity level to validate
        module_type: Optional module type (Cannon, Armor, Generator, Core) for compatibility check
        module_id: Optional module ID for additional validation
        
    Returns:
        Dict containing validation results with detailed information
    """
    validation_result = {
        'valid': True,
        'errors': [],
        'warnings': [],
        'details': {
            'enum_id': enum_id,
            'rarity': rarity,
            'module_type': module_type,
            'module_id': module_id,
            'substat_name': None,
            'substat_unit': None,
            'substat_value': None,
            'applies_to': None,
            'rarity_colors': None
        }
    }
    
    logger.info("Starting comprehensive validation", 
                enum_id=enum_id, rarity=rarity, module_type=module_type, module_id=module_id)
    
    # 1. Validate enum_id exists
    if enum_id not in module_lookups['substat_values']:
        validation_result['valid'] = False
        validation_result['errors'].append(f"Invalid enum_id: {enum_id} does not exist")
        logger.error("Invalid enum_id", enum_id=enum_id)
        return validation_result
    
    substat_data = module_lookups['substat_values'][enum_id]
    validation_result['details']['substat_name'] = substat_data.get('name', 'Unknown')
    
    # 2. Validate rarity exists in rarity_colors
    if rarity not in module_lookups['rarity_colors']:
        validation_result['valid'] = False
        validation_result['errors'].append(f"Invalid rarity: {rarity} does not exist")
        logger.error("Invalid rarity", rarity=rarity)
        return validation_result
    
    validation_result['details']['rarity_colors'] = module_lookups['rarity_colors'][rarity]
    
    # 3. Validate substat has required fields
    required_fields = ['name', 'unit', 'applies_to', 'values']
    for field in required_fields:
        if field not in substat_data:
            validation_result['valid'] = False
            validation_result['errors'].append(f"Missing required field '{field}' for enum_id {enum_id}")
            logger.error("Missing required field", field=field, enum_id=enum_id)
    
    if not validation_result['valid']:
        return validation_result
    
    # 4. Validate substat value exists for this rarity
    if rarity not in substat_data['values']:
        validation_result['valid'] = False
        validation_result['errors'].append(f"Substat {substat_data['name']} (ID: {enum_id}) does not have a value for rarity {rarity}")
        logger.error("Substat value not found for rarity", 
                    enum_id=enum_id, substat_name=substat_data['name'], rarity=rarity)
        return validation_result
    
    # 5. Validate substat value is not null/empty
    substat_value = substat_data['values'][rarity]
    if substat_value is None:
        validation_result['valid'] = False
        validation_result['errors'].append(f"Substat {substat_data['name']} (ID: {enum_id}) has null value for rarity {rarity}")
        logger.error("Null substat value", enum_id=enum_id, substat_name=substat_data['name'], rarity=rarity)
        return validation_result
    
    validation_result['details']['substat_value'] = substat_value
    validation_result['details']['substat_unit'] = substat_data['unit']
    validation_result['details']['applies_to'] = substat_data['applies_to']
    
    # 6. Validate module type compatibility (if provided)
    if module_type is not None:
        if module_type != substat_data['applies_to']:
            validation_result['warnings'].append(
                f"Module type '{module_type}' may not be compatible with substat '{substat_data['name']}' "
                f"which applies to '{substat_data['applies_to']}'"
            )
            logger.warning("Potential module type incompatibility", 
                          module_type=module_type, applies_to=substat_data['applies_to'], 
                          substat_name=substat_data['name'])
    
    # 7. Validate module_id (if provided)
    if module_id is not None:
        # Check if module_id exists in module definitions
        if 'modules' in module_lookups and str(module_id) in module_lookups['modules']:
            module_data = module_lookups['modules'][str(module_id)]
            module_type_from_id = module_data.get('type', 'Unknown')
            
            if module_type_from_id != substat_data['applies_to']:
                validation_result['warnings'].append(
                    f"Module ID {module_id} is type '{module_type_from_id}' but substat '{substat_data['name']}' "
                    f"applies to '{substat_data['applies_to']}'"
                )
                logger.warning("Module ID type mismatch", 
                              module_id=module_id, module_type=module_type_from_id, 
                              applies_to=substat_data['applies_to'])
        else:
            validation_result['warnings'].append(f"Module ID {module_id} not found in module definitions")
            logger.warning("Module ID not found", module_id=module_id)
    
    # 8. Validate rarity color definitions
    rarity_colors = module_lookups['rarity_colors'][rarity]
    if 'light_color' not in rarity_colors or 'dark_color' not in rarity_colors:
        validation_result['warnings'].append(f"Missing color definitions for rarity {rarity}")
        logger.warning("Missing color definitions", rarity=rarity)
    
    # 9. Check for zero values (might be intentional but worth noting)
    if isinstance(substat_value, (int, float)) and substat_value == 0:
        validation_result['warnings'].append(f"Substat {substat_data['name']} has zero value for rarity {rarity}")
        logger.debug("Zero substat value", enum_id=enum_id, substat_name=substat_data['name'], rarity=rarity)
    
    logger.info("Validation completed", 
                valid=validation_result['valid'], 
                error_count=len(validation_result['errors']),
                warning_count=len(validation_result['warnings']))
    
    return validation_result

def validate_module_combination(module_id: int, rarity: str, substat_enum_id: int) -> Dict[str, Any]:
    """
    Validate a complete module combination including module ID, rarity, and substat.
    
    Args:
        module_id: The module ID to validate
        rarity: The rarity level
        substat_enum_id: The substat enum ID
        
    Returns:
        Dict containing comprehensive validation results
    """
    validation_result = {
        'valid': True,
        'errors': [],
        'warnings': [],
        'details': {
            'module_id': module_id,
            'rarity': rarity,
            'substat_enum_id': substat_enum_id,
            'module_name': None,
            'module_type': None,
            'substat_name': None,
            'compatibility': 'unknown'
        }
    }
    
    logger.info("Starting module combination validation", 
                module_id=module_id, rarity=rarity, substat_enum_id=substat_enum_id)
    
    # 1. Validate module exists
    if 'modules' not in module_lookups or str(module_id) not in module_lookups['modules']:
        validation_result['valid'] = False
        validation_result['errors'].append(f"Module ID {module_id} does not exist")
        logger.error("Module ID not found", module_id=module_id)
        return validation_result
    
    module_data = module_lookups['modules'][str(module_id)]
    validation_result['details']['module_name'] = module_data.get('name', 'Unknown')
    validation_result['details']['module_type'] = module_data.get('type', 'Unknown')
    
    # 2. Validate substat
    substat_validation = validate(substat_enum_id, rarity, module_data.get('type'))
    if not substat_validation['valid']:
        validation_result['valid'] = False
        validation_result['errors'].extend(substat_validation['errors'])
    
    validation_result['warnings'].extend(substat_validation['warnings'])
    validation_result['details']['substat_name'] = substat_validation['details']['substat_name']
    
    # 3. Check compatibility
    if substat_validation['details']['applies_to'] == module_data.get('type'):
        validation_result['details']['compatibility'] = 'compatible'
    elif substat_validation['details']['applies_to'] != module_data.get('type'):
        validation_result['details']['compatibility'] = 'incompatible'
        validation_result['warnings'].append(
            f"Module '{module_data.get('name')}' (type: {module_data.get('type')}) "
            f"may not be compatible with substat '{substat_validation['details']['substat_name']}' "
            f"(applies to: {substat_validation['details']['applies_to']})"
        )
    
    logger.info("Module combination validation completed", 
                valid=validation_result['valid'],
                compatibility=validation_result['details']['compatibility'])
    
    return validation_result

def print_validation_result(validation_result: Dict[str, Any], show_details: bool = True):
    """
    Print validation results in a formatted way.
    
    Args:
        validation_result: The validation result dictionary
        show_details: Whether to show detailed information
    """
    if validation_result['valid']:
        print(f"✅ VALID: {validation_result['details']['substat_name']} (ID: {validation_result['details']['enum_id']}) at {validation_result['details']['rarity']} rarity")
    else:
        print(f"❌ INVALID: {validation_result['details']['substat_name']} (ID: {validation_result['details']['enum_id']}) at {validation_result['details']['rarity']} rarity")
    
    if validation_result['errors']:
        print("  Errors:")
        for error in validation_result['errors']:
            print(f"    ❌ {error}")
    
    if validation_result['warnings']:
        print("  Warnings:")
        for warning in validation_result['warnings']:
            print(f"    ⚠️  {warning}")
    
    if show_details and validation_result['details']['substat_value'] is not None:
        print(f"  Value: {validation_result['details']['substat_value']}{validation_result['details']['substat_unit']}")
        if validation_result['details']['applies_to']:
            print(f"  Applies to: {validation_result['details']['applies_to']}")

def print_colored_substat_full(enum_id, rarity):
    substat_name = get_substat_name(enum_id)
    substat_value_formatted = get_substat_value_formatted(enum_id, rarity)
    substat_light_color = get_substat_light_color(rarity)
    substat_dark_color = get_substat_dark_color(rarity)
    print(print_colored(substat_value_formatted, substat_dark_color) + " " + print_colored(substat_name, substat_light_color))
