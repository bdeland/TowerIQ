/**
 * Query composition utility for dynamic dashboard variables
 * Replaces placeholders in SQL queries with actual filter conditions
 *
 * WARNING: This performs client-side query composition which has inherent security risks.
 * Ideally, variable substitution should happen server-side with proper parameterization.
 * This implementation includes validation to mitigate injection risks.
 */

/**
 * Sanitize a value to prevent SQL injection
 * Only allows alphanumeric characters, underscores, hyphens, and dots
 */
function sanitizeValue(value: any): string {
  const str = String(value);
  // Only allow safe characters: alphanumeric, underscore, hyphen, dot
  if (!/^[a-zA-Z0-9_.-]+$/.test(str)) {
    console.warn(
      `Query composition: Rejected potentially unsafe value: ${str}`
    );
    throw new Error(`Invalid value in query variable: ${str}`);
  }
  return str;
}

/**
 * Sanitize an integer value for LIMIT clauses
 */
function sanitizeInteger(value: any): number {
  const parsed = parseInt(String(value), 10);
  if (isNaN(parsed) || parsed < 0 || parsed > 1000000) {
    console.warn(`Query composition: Invalid integer value: ${value}`);
    throw new Error(`Invalid integer value: ${value}`);
  }
  return parsed;
}

export function composeQuery(
  rawQuery: string,
  variables: Record<string, any>
): string {
  let finalQuery = rawQuery;

  try {
    // Handle tier filter
    const tierValue = variables.tier;
    if (finalQuery.includes("${tier_filter}")) {
      let tierClause = "";
      if (
        Array.isArray(tierValue) &&
        tierValue.length > 0 &&
        !tierValue.includes("all")
      ) {
        // Sanitize each tier value
        const safeTiers = tierValue
          .map((t) => {
            if (typeof t === "number" && Number.isFinite(t)) {
              return String(t);
            }
            // Sanitize string values
            const sanitized = sanitizeValue(t);
            return `'${sanitized}'`;
          })
          .join(",");

        // Check if there's already a WHERE clause in the query
        if (finalQuery.toLowerCase().includes("where")) {
          tierClause = `AND tier IN (${safeTiers})`;
        } else {
          tierClause = `WHERE tier IN (${safeTiers})`;
        }
      }
      finalQuery = finalQuery.replace("${tier_filter}", tierClause);
    }

    // Handle limit clause
    const limitValue = variables.num_runs;
    if (finalQuery.includes("${limit_clause}")) {
      let limitClause = "";
      if (limitValue && limitValue !== "all") {
        const safeLimit = sanitizeInteger(limitValue);
        limitClause = `LIMIT ${safeLimit}`;
      }
      finalQuery = finalQuery.replace("${limit_clause}", limitClause);
    }

    // Check for any remaining unresolved placeholders
    const unresolvedPlaceholders = finalQuery.match(/\$\{[^}]+\}/g);
    if (unresolvedPlaceholders) {
      console.warn(
        `Query composition: Unresolved placeholders found: ${unresolvedPlaceholders.join(
          ", "
        )}`
      );
    }

    // Clean up extra whitespace and return
    return finalQuery.replace(/\s+/g, " ").trim();
  } catch (error) {
    console.error("Query composition error:", error);
    // Return original query if composition fails to prevent breaking the UI
    return rawQuery;
  }
}
