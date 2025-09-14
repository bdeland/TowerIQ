/**
 * Query composition utility for dynamic dashboard variables
 * Replaces placeholders in SQL queries with actual filter conditions
 */

export function composeQuery(rawQuery: string, variables: Record<string, any>): string {
  let finalQuery = rawQuery;

  // Handle tier filter
  const tierValue = variables.tier;
  if (finalQuery.includes('${tier_filter}')) {
    let tierClause = '';
    if (Array.isArray(tierValue) && tierValue.length > 0 && !tierValue.includes('all')) {
      const safeTiers = tierValue.map(t => typeof t === 'number' ? t : `'${String(t)}'`).join(',');
      tierClause = `WHERE tier IN (${safeTiers})`;
    }
    finalQuery = finalQuery.replace('${tier_filter}', tierClause);
  }

  // Handle limit clause
  const limitValue = variables.num_runs;
  if (finalQuery.includes('${limit_clause}')) {
    let limitClause = '';
    if (limitValue && limitValue !== 'all') {
      limitClause = `LIMIT ${parseInt(String(limitValue), 10)}`;
    }
    finalQuery = finalQuery.replace('${limit_clause}', limitClause);
  }

  // Clean up extra whitespace and return
  return finalQuery.replace(/\s+/g, ' ').trim();
}
