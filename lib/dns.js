/**
 * DNS Security Analysis Module
 * Checks for common DNS security issues and misconfigurations
 */
const dns = require('dns');
const { promisify } = require('util');
// Note: dnsbl is an ESM module, we're implementing our own simple check instead

// Convert DNS functions to promises
const resolve = promisify(dns.resolve);
const resolveMx = promisify(dns.resolveMx);
const resolveTxt = promisify(dns.resolveTxt);
const resolveNs = promisify(dns.resolveNs);
const resolveCaa = promisify(dns.resolveCaa);

/**
 * Check DNS security for a domain
 * @param {string} domain - Domain to check
 * @returns {Promise<object>} - DNS security analysis
 */
async function checkDns(domain) {
  try {
    const results = {
      domain,
      nameservers: [],
      mxRecords: [],
      txtRecords: [],
      caaRecords: [],
      dmarc: null,
      spf: null,
      blacklists: [],
      analysis: {
        issues: [],
        warnings: [],
        recommendations: []
      }
    };

    // Check nameservers
    try {
      results.nameservers = await resolveNs(domain);
      if (results.nameservers.length < 2) {
        results.analysis.warnings.push('Domain has fewer than 2 nameservers');
      }
    } catch (error) {
      results.analysis.issues.push('Failed to retrieve nameservers');
    }

    // Check MX records
    try {
      results.mxRecords = await resolveMx(domain);
      if (results.mxRecords.length === 0) {
        results.analysis.warnings.push('No MX records found. Email delivery may be affected.');
      }
    } catch (error) {
      // Non-critical error, might not be used for email
    }

    // Check TXT records for SPF and DMARC
    try {
      const txtRecords = await resolveTxt(domain);
      results.txtRecords = txtRecords;

      // Check SPF
      const spfRecord = txtRecords.find(record => 
        record.join('').toLowerCase().startsWith('v=spf1')
      );
      
      results.spf = spfRecord ? spfRecord.join('') : null;
      
      if (!results.spf) {
        results.analysis.warnings.push('No SPF record found');
        results.analysis.recommendations.push(
          'Add an SPF record to protect against email spoofing'
        );
      }

      // Check DMARC
      try {
        const dmarcRecords = await resolveTxt(`_dmarc.${domain}`);
        const dmarcRecord = dmarcRecords.find(record => 
          record.join('').toLowerCase().startsWith('v=dmarc1')
        );
        
        results.dmarc = dmarcRecord ? dmarcRecord.join('') : null;
        
        if (!results.dmarc) {
          results.analysis.warnings.push('No DMARC record found');
          results.analysis.recommendations.push(
            'Add a DMARC record to protect against email spoofing'
          );
        } else if (results.dmarc.includes('p=none')) {
          results.analysis.warnings.push('DMARC policy is set to none');
          results.analysis.recommendations.push(
            'Consider setting DMARC policy to quarantine or reject'
          );
        }
      } catch (error) {
        results.analysis.warnings.push('No DMARC record found');
      }
    } catch (error) {
      results.analysis.warnings.push('Failed to retrieve TXT records');
    }

    // Check CAA records
    try {
      results.caaRecords = await resolveCaa(domain);
      
      // If no CAA records, any CA can issue certs
      if (results.caaRecords.length === 0) {
        results.analysis.warnings.push('No CAA records found');
        results.analysis.recommendations.push(
          'Add CAA records to restrict which CAs can issue certificates for your domain'
        );
      }
    } catch (error) {
      // CAA records may not exist, not critical
    }    // Check if domain is on any blacklists (simplified version without dnsbl dependency)
    try {
      const blacklists = [
        'zen.spamhaus.org',
        'bl.spamcop.net',
        'dnsbl.sorbs.net'
      ];
      
      const checkBlacklist = async (domain, blacklistServer) => {
        // Reverse the IP or use the domain
        let lookupDomain = domain;
        
        // If it's an IP address, reverse it for DNSBL lookup
        if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(domain)) {
          lookupDomain = domain.split('.').reverse().join('.') + '.' + blacklistServer;
        } else {
          // Use the domain directly
          lookupDomain = domain + '.' + blacklistServer;
        }
        
        try {
          // If this resolves without error, it's blacklisted
          const addresses = await resolve(lookupDomain, 'A');
          return { blacklist: blacklistServer, listed: addresses.length > 0 };
        } catch (err) {
          // NXDOMAIN = not blacklisted (expected)
          return { blacklist: blacklistServer, listed: false };
        }
      };
      
      const blacklistPromises = blacklists.map(blacklist => checkBlacklist(domain, blacklist));
      const blacklistResults = await Promise.all(blacklistPromises);
      results.blacklists = blacklistResults;
      
      const listedOn = blacklistResults.filter(result => result.listed);
      
      if (listedOn.length > 0) {
        results.analysis.issues.push(
          `Domain is listed on ${listedOn.length} blacklist(s): ${listedOn.map(r => r.blacklist).join(', ')}`
        );
      }
    } catch (error) {
      // Non-critical, just skip blacklist checks
      results.blacklists = [];
    }

    return results;
  } catch (error) {
    return {
      domain,
      error: true,
      message: error.message
    };
  }
}

/**
 * Analyze DNS security for improving email deliverability and domain security
 * @param {object} dnsData - Output from checkDns
 * @returns {object} - Security assessment
 */
function analyzeDnsSecurity(dnsData) {
  if (dnsData.error) {
    return { status: 'error', message: dnsData.message };
  }
  
  const assessment = {
    score: 0,
    maxScore: 100,
    issues: dnsData.analysis.issues || [],
    warnings: dnsData.analysis.warnings || [],
    recommendations: dnsData.analysis.recommendations || []
  };

  // Start with 100 points and subtract for issues
  let score = 100;

  // Critical issues (-20 each)
  if (dnsData.blacklists.some(bl => bl.listed)) {
    score -= 20;
  }
  
  // Major issues (-15 each)
  if (!dnsData.spf) {
    score -= 15;
  }
  
  if (!dnsData.dmarc) {
    score -= 15;
  }
  
  // Minor issues (-10 each)
  if (dnsData.nameservers.length < 2) {
    score -= 10;
  }
  
  if (dnsData.dmarc && dnsData.dmarc.includes('p=none')) {
    score -= 10;
  }
  
  if (dnsData.caaRecords.length === 0) {
    score -= 10;
  }
  
  // Very minor issues (-5 each)
  if (dnsData.mxRecords.length === 0) {
    score -= 5;
  }
  
  // Ensure score is between 0 and 100
  assessment.score = Math.max(0, Math.min(100, score));
  
  // Calculate percentage
  assessment.percentage = assessment.score;
  
  // Assign rating
  if (assessment.score >= 90) {
    assessment.rating = 'Excellent';
  } else if (assessment.score >= 70) {
    assessment.rating = 'Good';
  } else if (assessment.score >= 50) {
    assessment.rating = 'Fair';
  } else {
    assessment.rating = 'Poor';
  }
  
  return assessment;
}

module.exports = { checkDns, analyzeDnsSecurity };
