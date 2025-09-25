/**
 * DashboardVariables Class
 * 
 * Manages dashboard variables with validation, query-backed options,
 * and SQL query composition. Replaces the scattered variable logic
 * from multiple contexts with a centralized, type-safe system.
 */

import { z } from 'zod';
import { 
  VariableDefinition, 
  VariableOption, 
  VariableSet, 
  ValidationResult,
  QueryVariableOptions,
  RangeVariableOptions,
  VariableError
} from './types';
import { API_CONFIG } from '../../config/environment';

export class DashboardVariables {
  private _definitions: Map<string, VariableDefinition>;
  private values: Map<string, any>;
  private options: Map<string, VariableOption[]>;
  private validators: Map<string, z.ZodSchema>;
  private optionsCache: Map<string, { options: VariableOption[]; timestamp: number }>;
  
  private readonly CACHE_TTL = 300000; // 5 minutes
  
  constructor(definitions: VariableDefinition[] = []) {
    this._definitions = new Map();
    this.values = new Map();
    this.options = new Map();
    this.validators = new Map();
    this.optionsCache = new Map();
    
    // Initialize with provided definitions
    definitions.forEach(def => this.addDefinition(def));
  }
  
  // ========================================================================
  // Definition Management
  // ========================================================================
  
  get definitions(): Map<string, VariableDefinition> {
    return new Map(this._definitions);
  }
  
  addDefinition(definition: VariableDefinition): void {
    this._definitions.set(definition.name, definition);
    
    // Set default value
    this.values.set(definition.name, definition.defaultValue);
    
    // Set static options if provided
    if (definition.options) {
      this.options.set(definition.name, definition.options);
    }
    
    // Create validator
    if (definition.validation) {
      this.validators.set(definition.name, definition.validation);
    } else {
      // Create default validator based on type
      this.validators.set(definition.name, this.createDefaultValidator(definition));
    }
  }
  
  removeDefinition(name: string): void {
    this._definitions.delete(name);
    this.values.delete(name);
    this.options.delete(name);
    this.validators.delete(name);
    this.optionsCache.delete(name);
  }
  
  getDefinition(name: string): VariableDefinition | undefined {
    return this._definitions.get(name);
  }
  
  getAllDefinitions(): VariableDefinition[] {
    return Array.from(this._definitions.values());
  }
  
  private createDefaultValidator(definition: VariableDefinition): z.ZodSchema {
    switch (definition.type) {
      case 'static':
        if (Array.isArray(definition.defaultValue)) {
          return z.array(z.any()).min(definition.required ? 1 : 0);
        }
        return definition.required ? z.any().refine(val => val != null) : z.any();
        
      case 'query':
        return definition.required ? z.any().refine(val => val != null) : z.any();
        
      case 'range':
        const rangeOptions = definition.rangeOptions;
        if (rangeOptions) {
          return z.number()
            .min(rangeOptions.min)
            .max(rangeOptions.max)
            .multipleOf(rangeOptions.step || 1);
        }
        return z.number();
        
      case 'custom':
        return definition.required ? z.any().refine(val => val != null) : z.any();
        
      default:
        return z.any();
    }
  }
  
  // ========================================================================
  // Value Management
  // ========================================================================
  
  updateValue(name: string, value: any): ValidationResult {
    const definition = this._definitions.get(name);
    if (!definition) {
      throw new VariableError(`Variable definition not found: ${name}`, 'VAR_NOT_FOUND', name);
    }
    
    const validator = this.validators.get(name);
    if (!validator) {
      throw new VariableError(`Validator not found for variable: ${name}`, 'VALIDATOR_NOT_FOUND', name);
    }
    
    try {
      // Validate the value
      const validatedValue = validator.parse(value);
      
      // Store the validated value
      this.values.set(name, validatedValue);
      
      return {
        isValid: true,
        errors: [],
        warnings: []
      };
      
    } catch (error: unknown) {
      if (error instanceof z.ZodError) {
        return {
          isValid: false,
          errors: error.issues.map((issue) => `${name}: ${issue.message}`),
          warnings: []
        };
      }

      const err = error instanceof Error ? error : new Error(String(error));

      return {
        isValid: false,
        errors: [`${name}: Validation failed - ${err.message}`],
        warnings: []
      };
    }
  }
  
  getValue(name: string): any {
    if (!this._definitions.has(name)) {
      throw new VariableError(`Variable definition not found: ${name}`, 'VAR_NOT_FOUND', name);
    }
    
    return this.values.get(name);
  }
  
  getValues(): VariableSet {
    const values: VariableSet = {};
    for (const [name, value] of this.values) {
      values[name] = value;
    }
    return values;
  }
  
  resetToDefaults(): void {
    for (const [name, definition] of this._definitions) {
      this.values.set(name, definition.defaultValue);
    }
  }
  
  resetValue(name: string): void {
    const definition = this._definitions.get(name);
    if (!definition) {
      throw new VariableError(`Variable definition not found: ${name}`, 'VAR_NOT_FOUND', name);
    }
    
    this.values.set(name, definition.defaultValue);
  }
  
  // ========================================================================
  // Validation
  // ========================================================================
  
  validate(name: string): ValidationResult {
    const value = this.values.get(name);
    return this.updateValue(name, value);
  }
  
  validateAll(): ValidationResult[] {
    const results: ValidationResult[] = [];
    
    for (const name of this._definitions.keys()) {
      results.push(this.validate(name));
    }
    
    return results;
  }
  
  isValid(): boolean {
    const results = this.validateAll();
    return results.every(result => result.isValid);
  }
  
  getValidationErrors(): string[] {
    const results = this.validateAll();
    const errors: string[] = [];
    
    for (const result of results) {
      errors.push(...result.errors);
    }
    
    return errors;
  }
  
  // ========================================================================
  // Options Management
  // ========================================================================
  
  async loadDynamicOptions(variableName: string): Promise<VariableOption[]> {
    const definition = this._definitions.get(variableName);
    if (!definition) {
      throw new VariableError(`Variable definition not found: ${variableName}`, 'VAR_NOT_FOUND', variableName);
    }
    
    if (definition.type !== 'query' || !definition.queryOptions) {
      throw new VariableError(`Variable ${variableName} is not a query variable`, 'NOT_QUERY_VAR', variableName);
    }
    
    // Check cache first
    const cached = this.optionsCache.get(variableName);
    if (cached && (Date.now() - cached.timestamp) < this.CACHE_TTL) {
      return cached.options;
    }
    
    try {
      // Execute query to get options
      const options = await this.executeOptionsQuery(definition.queryOptions);
      
      // Cache the results
      this.optionsCache.set(variableName, {
        options,
        timestamp: Date.now()
      });
      
      // Store in options map
      this.options.set(variableName, options);
      
      return options;
      
    } catch (error: unknown) {
      const err = error instanceof Error ? error : new Error(String(error));
      throw new VariableError(
        `Failed to load options for variable ${variableName}: ${err.message}`,
        'OPTIONS_LOAD_FAILED',
        variableName,
        undefined,
        { originalError: err }
      );
    }
  }
  
  private async executeOptionsQuery(queryOptions: QueryVariableOptions): Promise<VariableOption[]> {
    // This would integrate with the data source system
    // For now, we'll simulate the API call
    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}/v2/query`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          query: queryOptions.query,
          dataSourceId: queryOptions.dataSourceId
        })
      });
      
      if (!response.ok) {
        throw new Error(`Query failed: ${response.status} ${response.statusText}`);
      }
      
      const data = await response.json();
      
      // Transform data to VariableOption format
      return data.map((row: any) => ({
        value: row[queryOptions.valueField],
        label: queryOptions.labelField ? row[queryOptions.labelField] : String(row[queryOptions.valueField]),
        description: row.description || undefined
      }));
      
    } catch (error: unknown) {
      const err = error instanceof Error ? error : new Error(String(error));
      throw new Error(`Options query execution failed: ${err.message}`);
    }
  }
  
  getOptions(name: string): VariableOption[] {
    return this.options.get(name) || [];
  }
  
  hasOptions(name: string): boolean {
    return this.options.has(name) && this.options.get(name)!.length > 0;
  }
  
  clearOptionsCache(name?: string): void {
    if (name) {
      this.optionsCache.delete(name);
    } else {
      this.optionsCache.clear();
    }
  }
  
  // ========================================================================
  // Query Composition
  // ========================================================================
  
  getComposedQuery(rawQuery: string): string {
    let finalQuery = rawQuery;
    const values = this.getValues();
    
    // Handle tier_filter pattern
    if (finalQuery.includes('${tier_filter}')) {
      const tierClause = this.composeTierFilter(values.tier);
      finalQuery = finalQuery.replace('${tier_filter}', tierClause);
    }
    
    // Handle limit_clause pattern
    if (finalQuery.includes('${limit_clause}')) {
      const limitClause = this.composeLimitClause(values.num_runs);
      finalQuery = finalQuery.replace('${limit_clause}', limitClause);
    }
    
    // Handle any other variable patterns
    for (const [name, value] of this.values) {
      const pattern = `\${${name}}`;
      if (finalQuery.includes(pattern)) {
        const replacement = this.composeVariableReplacement(name, value);
        finalQuery = finalQuery.replace(new RegExp(pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), replacement);
      }
    }
    
    // Clean up whitespace
    return finalQuery.replace(/\s+/g, ' ').trim();
  }
  
  private composeTierFilter(tierValue: any): string {
    if (!tierValue) return '';
    
    if (Array.isArray(tierValue) && tierValue.length > 0 && !tierValue.includes('all')) {
      const safeTiers = tierValue
        .map(t => typeof t === 'number' ? t : `'${String(t)}'`)
        .join(',');
      return `AND tier IN (${safeTiers})`;
    }
    
    return '';
  }
  
  private composeLimitClause(limitValue: any): string {
    if (!limitValue || limitValue === 'all') return '';
    
    const limit = parseInt(String(limitValue), 10);
    if (isNaN(limit) || limit <= 0) return '';
    
    return `LIMIT ${limit}`;
  }
  
  private composeVariableReplacement(name: string, value: any): string {
    // Handle different variable types
    if (value === null || value === undefined) {
      return '';
    }
    
    if (Array.isArray(value)) {
      return value.map(v => `'${String(v)}'`).join(',');
    }
    
    if (typeof value === 'string') {
      return `'${value}'`;
    }
    
    return String(value);
  }
  
  hasUnresolvedPlaceholders(query: string): boolean {
    const placeholderPattern = /\$\{[^}]+\}/g;
    return placeholderPattern.test(query);
  }
  
  getUnresolvedPlaceholders(query: string): string[] {
    const placeholderPattern = /\$\{([^}]+)\}/g;
    const matches: string[] = [];
    let match;
    
    while ((match = placeholderPattern.exec(query)) !== null) {
      matches.push(match[1]);
    }
    
    return matches;
  }
  
  // ========================================================================
  // Serialization
  // ========================================================================
  
  serialize(): any {
    return {
      definitions: Array.from(this._definitions.entries()),
      values: Array.from(this.values.entries()),
      options: Array.from(this.options.entries())
    };
  }
  
  static deserialize(data: any): DashboardVariables {
    const variables = new DashboardVariables();
    
    if (data.definitions) {
      for (const [name, definition] of data.definitions) {
        variables.definitions.set(name, definition);
      }
    }
    
    if (data.values) {
      for (const [name, value] of data.values) {
        variables.values.set(name, value);
      }
    }
    
    if (data.options) {
      for (const [name, options] of data.options) {
        variables.options.set(name, options);
      }
    }
    
    // Rebuild validators
    for (const definition of variables.definitions.values()) {
      variables.validators.set(definition.name, variables.createDefaultValidator(definition));
    }
    
    return variables;
  }
  
  // ========================================================================
  // Utility Methods
  // ========================================================================
  
  clone(): DashboardVariables {
    const serialized = this.serialize();
    return DashboardVariables.deserialize(serialized);
  }
  
  isEmpty(): boolean {
    return this._definitions.size === 0;
  }
  
  getVariableNames(): string[] {
    return Array.from(this._definitions.keys());
  }
  
  hasVariable(name: string): boolean {
    return this._definitions.has(name);
  }
  
  getVariableCount(): number {
    return this._definitions.size;
  }
  
  // ========================================================================
  // Static Factory Methods
  // ========================================================================
  
  /**
   * Create variables for TowerIQ default dashboard
   */
  static createDefaultDashboardVariables(): DashboardVariables {
    const tierDefinition: VariableDefinition = {
      name: 'tier',
      type: 'query',
      label: 'Tier',
      description: 'Filter runs by tier',
      required: false,
      defaultValue: ['all'],
      queryOptions: {
        query: 'SELECT DISTINCT tier FROM runs WHERE tier IS NOT NULL ORDER BY tier ASC',
        dataSourceId: 'default-sqlite',
        valueField: 'tier',
        labelField: 'tier',
        refreshOnDashboardLoad: true
      },
      validation: z.array(z.union([z.string(), z.number()])).min(1)
    };
    
    const numRunsDefinition: VariableDefinition = {
      name: 'num_runs',
      type: 'static',
      label: 'Number of Last Runs',
      description: 'Limit the number of runs to display',
      required: false,
      defaultValue: 10,
      options: [
        { value: 'all', label: 'All Runs' },
        { value: 5, label: '5 Runs' },
        { value: 10, label: '10 Runs' },
        { value: 25, label: '25 Runs' },
        { value: 50, label: '50 Runs' },
        { value: 100, label: '100 Runs' }
      ],
      validation: z.union([z.string(), z.number().positive()])
    };
    
    return new DashboardVariables([tierDefinition, numRunsDefinition]);
  }
  
  /**
   * Create empty variables instance
   */
  static createEmpty(): DashboardVariables {
    return new DashboardVariables();
  }
}
