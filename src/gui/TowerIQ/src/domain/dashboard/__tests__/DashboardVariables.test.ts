/**
 * Unit Tests for DashboardVariables Class
 * 
 * Tests the variable management system with validation,
 * query composition, and options loading.
 */

import { z } from 'zod';
import { DashboardVariables } from '../DashboardVariables';
import { VariableDefinition } from '../types';

describe('DashboardVariables', () => {
  let variables: DashboardVariables;

  beforeEach(() => {
    variables = new DashboardVariables();
  });

  describe('Definition Management', () => {
    it('should add and retrieve variable definitions', () => {
      const definition: VariableDefinition = {
        name: 'test_var',
        type: 'static',
        label: 'Test Variable',
        description: 'A test variable',
        required: true,
        defaultValue: 'default',
        validation: z.string().min(1)
      };

      variables.addDefinition(definition);

      const retrieved = variables.getDefinition('test_var');
      expect(retrieved).toEqual(definition);
    });

    it('should remove variable definitions', () => {
      const definition: VariableDefinition = {
        name: 'test_var',
        type: 'static',
        label: 'Test Variable',
        required: false,
        defaultValue: 'default'
      };

      variables.addDefinition(definition);
      expect(variables.hasVariable('test_var')).toBe(true);

      variables.removeDefinition('test_var');
      expect(variables.hasVariable('test_var')).toBe(false);
    });

    it('should return all definitions', () => {
      const def1: VariableDefinition = {
        name: 'var1',
        type: 'static',
        label: 'Variable 1',
        required: false,
        defaultValue: 'value1'
      };

      const def2: VariableDefinition = {
        name: 'var2',
        type: 'static',
        label: 'Variable 2',
        required: false,
        defaultValue: 'value2'
      };

      variables.addDefinition(def1);
      variables.addDefinition(def2);

      const allDefs = variables.getAllDefinitions();
      expect(allDefs).toHaveLength(2);
      expect(allDefs.map(d => d.name)).toContain('var1');
      expect(allDefs.map(d => d.name)).toContain('var2');
    });
  });

  describe('Value Management', () => {
    beforeEach(() => {
      const definition: VariableDefinition = {
        name: 'test_var',
        type: 'static',
        label: 'Test Variable',
        required: true,
        defaultValue: 'default',
        validation: z.string().min(1)
      };
      variables.addDefinition(definition);
    });

    it('should set default values when adding definitions', () => {
      expect(variables.getValue('test_var')).toBe('default');
    });

    it('should update variable values with validation', () => {
      const result = variables.updateValue('test_var', 'new_value');
      
      expect(result.isValid).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(variables.getValue('test_var')).toBe('new_value');
    });

    it('should reject invalid values', () => {
      const result = variables.updateValue('test_var', ''); // Empty string should fail min(1)
      
      expect(result.isValid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(variables.getValue('test_var')).toBe('default'); // Should remain unchanged
    });

    it('should throw error for non-existent variables', () => {
      expect(() => {
        variables.updateValue('non_existent', 'value');
      }).toThrow('Variable definition not found: non_existent');
    });

    it('should get all variable values', () => {
      variables.updateValue('test_var', 'updated_value');
      
      const values = variables.getValues();
      expect(values).toEqual({ test_var: 'updated_value' });
    });

    it('should reset values to defaults', () => {
      variables.updateValue('test_var', 'changed_value');
      expect(variables.getValue('test_var')).toBe('changed_value');

      variables.resetToDefaults();
      expect(variables.getValue('test_var')).toBe('default');
    });

    it('should reset individual variable values', () => {
      variables.updateValue('test_var', 'changed_value');
      expect(variables.getValue('test_var')).toBe('changed_value');

      variables.resetValue('test_var');
      expect(variables.getValue('test_var')).toBe('default');
    });
  });

  describe('Validation', () => {
    beforeEach(() => {
      const numericDef: VariableDefinition = {
        name: 'numeric_var',
        type: 'range',
        label: 'Numeric Variable',
        required: true,
        defaultValue: 5,
        rangeOptions: {
          min: 1,
          max: 10,
          step: 1
        }
      };

      const arrayDef: VariableDefinition = {
        name: 'array_var',
        type: 'static',
        label: 'Array Variable',
        required: true,
        defaultValue: ['all'],
        validation: z.array(z.string()).min(1)
      };

      variables.addDefinition(numericDef);
      variables.addDefinition(arrayDef);
    });

    it('should validate numeric ranges', () => {
      // Valid value
      let result = variables.updateValue('numeric_var', 7);
      expect(result.isValid).toBe(true);

      // Invalid value - too high
      result = variables.updateValue('numeric_var', 15);
      expect(result.isValid).toBe(false);

      // Invalid value - too low
      result = variables.updateValue('numeric_var', 0);
      expect(result.isValid).toBe(false);
    });

    it('should validate arrays', () => {
      // Valid array
      let result = variables.updateValue('array_var', ['option1', 'option2']);
      expect(result.isValid).toBe(true);

      // Invalid - empty array
      result = variables.updateValue('array_var', []);
      expect(result.isValid).toBe(false);
    });

    it('should validate all variables', () => {
      // Set invalid values
      variables.updateValue('numeric_var', 20); // Will fail validation
      variables.updateValue('array_var', ['valid']);

      const results = variables.validateAll();
      expect(results).toHaveLength(2);
      
      const numericResult = results.find(r => r.errors.some(e => e.includes('numeric_var')));
      const arrayResult = results.find(r => r.errors.length === 0 || r.errors.some(e => e.includes('array_var')));
      
      expect(numericResult?.isValid).toBe(false);
      expect(arrayResult?.isValid).toBe(true);
    });

    it('should check overall validity', () => {
      // All valid
      variables.updateValue('numeric_var', 5);
      variables.updateValue('array_var', ['valid']);
      expect(variables.isValid()).toBe(true);

      // One invalid
      variables.updateValue('numeric_var', 20);
      expect(variables.isValid()).toBe(false);
    });
  });

  describe('Query Composition', () => {
    beforeEach(() => {
      const tierDef: VariableDefinition = {
        name: 'tier',
        type: 'static',
        label: 'Tier',
        required: false,
        defaultValue: ['all']
      };

      const limitDef: VariableDefinition = {
        name: 'num_runs',
        type: 'static',
        label: 'Number of Runs',
        required: false,
        defaultValue: 10
      };

      variables.addDefinition(tierDef);
      variables.addDefinition(limitDef);
    });

    it('should compose tier filter queries', () => {
      variables.updateValue('tier', [1, 2, 3]);
      
      const query = 'SELECT * FROM runs ${tier_filter} ORDER BY start_time';
      const composed = variables.getComposedQuery(query);
      
      expect(composed).toBe('SELECT * FROM runs AND tier IN (1,2,3) ORDER BY start_time');
    });

    it('should compose limit clauses', () => {
      variables.updateValue('num_runs', 25);
      
      const query = 'SELECT * FROM runs ORDER BY start_time ${limit_clause}';
      const composed = variables.getComposedQuery(query);
      
      expect(composed).toBe('SELECT * FROM runs ORDER BY start_time LIMIT 25');
    });

    it('should handle "all" tier values', () => {
      variables.updateValue('tier', ['all']);
      
      const query = 'SELECT * FROM runs ${tier_filter} ORDER BY start_time';
      const composed = variables.getComposedQuery(query);
      
      expect(composed).toBe('SELECT * FROM runs ORDER BY start_time');
    });

    it('should handle "all" limit values', () => {
      variables.updateValue('num_runs', 'all');
      
      const query = 'SELECT * FROM runs ORDER BY start_time ${limit_clause}';
      const composed = variables.getComposedQuery(query);
      
      expect(composed).toBe('SELECT * FROM runs ORDER BY start_time');
    });

    it('should compose complex queries with multiple variables', () => {
      variables.updateValue('tier', [5, 6]);
      variables.updateValue('num_runs', 50);
      
      const query = 'SELECT * FROM runs ${tier_filter} ORDER BY start_time ${limit_clause}';
      const composed = variables.getComposedQuery(query);
      
      expect(composed).toBe('SELECT * FROM runs AND tier IN (5,6) ORDER BY start_time LIMIT 50');
    });

    it('should detect unresolved placeholders', () => {
      const query = 'SELECT * FROM runs ${unknown_variable} ORDER BY start_time';
      
      expect(variables.hasUnresolvedPlaceholders(query)).toBe(true);
      
      const placeholders = variables.getUnresolvedPlaceholders(query);
      expect(placeholders).toEqual(['unknown_variable']);
    });

    it('should not detect resolved placeholders', () => {
      const query = 'SELECT * FROM runs ${tier_filter} ORDER BY start_time ${limit_clause}';
      const composed = variables.getComposedQuery(query);
      
      expect(variables.hasUnresolvedPlaceholders(composed)).toBe(false);
    });
  });

  describe('Static Factory Methods', () => {
    it('should create default dashboard variables', () => {
      const defaultVars = DashboardVariables.createDefaultDashboardVariables();
      
      expect(defaultVars.hasVariable('tier')).toBe(true);
      expect(defaultVars.hasVariable('num_runs')).toBe(true);
      
      expect(defaultVars.getValue('tier')).toEqual(['all']);
      expect(defaultVars.getValue('num_runs')).toBe(10);
    });

    it('should create empty variables instance', () => {
      const emptyVars = DashboardVariables.createEmpty();
      
      expect(emptyVars.isEmpty()).toBe(true);
      expect(emptyVars.getVariableCount()).toBe(0);
    });
  });

  describe('Serialization', () => {
    beforeEach(() => {
      const definition: VariableDefinition = {
        name: 'test_var',
        type: 'static',
        label: 'Test Variable',
        required: false,
        defaultValue: 'default'
      };

      variables.addDefinition(definition);
      variables.updateValue('test_var', 'updated');
    });

    it('should serialize and deserialize correctly', () => {
      const serialized = variables.serialize();
      const deserialized = DashboardVariables.deserialize(serialized);
      
      expect(deserialized.hasVariable('test_var')).toBe(true);
      expect(deserialized.getValue('test_var')).toBe('updated');
      
      const definition = deserialized.getDefinition('test_var');
      expect(definition?.label).toBe('Test Variable');
    });

    it('should clone variables correctly', () => {
      const cloned = variables.clone();
      
      expect(cloned.hasVariable('test_var')).toBe(true);
      expect(cloned.getValue('test_var')).toBe('updated');
      
      // Ensure it's a separate instance
      cloned.updateValue('test_var', 'different');
      expect(variables.getValue('test_var')).toBe('updated');
      expect(cloned.getValue('test_var')).toBe('different');
    });
  });

  describe('Utility Methods', () => {
    beforeEach(() => {
      const def1: VariableDefinition = {
        name: 'var1',
        type: 'static',
        label: 'Variable 1',
        required: false,
        defaultValue: 'value1'
      };

      const def2: VariableDefinition = {
        name: 'var2',
        type: 'static',
        label: 'Variable 2',
        required: false,
        defaultValue: 'value2'
      };

      variables.addDefinition(def1);
      variables.addDefinition(def2);
    });

    it('should check if empty', () => {
      const emptyVars = new DashboardVariables();
      expect(emptyVars.isEmpty()).toBe(true);
      expect(variables.isEmpty()).toBe(false);
    });

    it('should get variable names', () => {
      const names = variables.getVariableNames();
      expect(names).toHaveLength(2);
      expect(names).toContain('var1');
      expect(names).toContain('var2');
    });

    it('should check if variable exists', () => {
      expect(variables.hasVariable('var1')).toBe(true);
      expect(variables.hasVariable('non_existent')).toBe(false);
    });

    it('should get variable count', () => {
      expect(variables.getVariableCount()).toBe(2);
    });
  });
});
