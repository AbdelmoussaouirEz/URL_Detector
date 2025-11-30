from typing import Dict, List
import logging

logger = logging.getLogger(__name__)

class ScoringSystem:
    """Calculate final security score from all checkers"""
    
    def __init__(self):
        self.risk_thresholds = {
            'SAFE': 0.0,
            'LOW': 0.22,
            'MEDIUM': 0.44,
            'HIGH': 0.66,
            'CRITICAL': 0.78
        }
    
    def calculate_score(self, checks: List[Dict]) -> Dict:
        """
        Calculate final security score
        
        Args:
            checks: List of checker results
            
        Returns:
            Dictionary with score details
        """
        try:
            total_checks = len(checks)
            flags_raised = sum(1 for check in checks if check['flagged'])
            
            # Calculate percentage
            risk_percentage = (flags_raised / total_checks * 100) if total_checks > 0 else 0
            risk_ratio = flags_raised / total_checks if total_checks > 0 else 0
            
            # Determine risk level
            risk_level = self._get_risk_level(risk_ratio)
            
            # Determine if safe
            is_safe = flags_raised == 0
            
            # Generate recommendation
            recommendation = self._get_recommendation(risk_level, flags_raised, checks)
            
            result = {
                'risk_score': f"{flags_raised}/{total_checks}",
                'risk_percentage': round(risk_percentage, 2),
                'risk_level': risk_level,
                'is_safe': is_safe,
                'total_checks': total_checks,
                'flags_raised': flags_raised,
                'recommendation': recommendation
            }
            
            logger.info(f"Score calculated: {flags_raised}/{total_checks} ({risk_level})")
            
            return result
            
        except Exception as e:
            logger.error(f"Error calculating score: {str(e)}")
            raise
    
    def _get_risk_level(self, ratio: float) -> str:
        """
        Determine risk level from ratio
        
        Args:
            ratio: Flags raised / total checks
            
        Returns:
            Risk level string
        """
        if ratio == 0.0:
            return 'SAFE'
        elif ratio <= 0.22:
            return 'LOW'
        elif ratio <= 0.44:
            return 'MEDIUM'
        elif ratio <= 0.66:
            return 'HIGH'
        else:
            return 'CRITICAL'
    
    def _get_recommendation(self, risk_level: str, flags_raised: int, checks: List[Dict]) -> str:
        """
        Generate user-friendly recommendation
        
        Args:
            risk_level: Calculated risk level
            flags_raised: Number of checks that flagged issues
            checks: List of all check results
            
        Returns:
            Recommendation string
        """
        if risk_level == 'SAFE':
            return "✅ SAFE: No security concerns detected. This URL appears to be safe."
        
        elif risk_level == 'LOW':
            flagged_names = [c['name'] for c in checks if c['flagged']]
            return f"⚠️ LOW RISK: Minor concern detected ({', '.join(flagged_names)}). Proceed with caution."
        
        elif risk_level == 'MEDIUM':
            flagged_names = [c['name'] for c in checks if c['flagged']]
            return f"⚠️ MEDIUM RISK: Multiple concerns detected ({', '.join(flagged_names)}). Exercise caution."
        
        elif risk_level == 'HIGH':
            return f"🚨 HIGH RISK: {flags_raised} security concerns detected. Strongly recommend avoiding this URL."
        
        else:  # CRITICAL
            return f"🔴 CRITICAL RISK: {flags_raised} serious security threats detected. DO NOT VISIT THIS URL!"
    
    def format_checks_summary(self, checks: List[Dict]) -> str:
        """
        Create a text summary of all checks
        
        Args:
            checks: List of check results
            
        Returns:
            Formatted summary string
        """
        summary_lines = []
        
        for check in checks:
            status = "❌" if check['flagged'] else "✅"
            summary_lines.append(f"{status} {check['name']}: {check['reason']}")
        
        return "\n".join(summary_lines)