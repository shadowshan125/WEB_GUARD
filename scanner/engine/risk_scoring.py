class RiskScoringEngine:
    @staticmethod
    def get_severity_score(severity):
        """Returns a numerical score based on the severity name."""
        scores = {
            'CRITICAL': 10.0,
            'HIGH': 8.0,
            'MEDIUM': 5.0,
            'LOW': 2.0,
            'INFO': 0.0
        }
        return scores.get(severity.upper(), 0.0)

    @staticmethod
    def calculate_overall_risk(vulnerabilities):
        """Calculates an overall risk score from a list of vulnerabilities."""
        if not vulnerabilities:
            return 'INFO', 0.0
            
        total_score = 0.0
        highest_severity = 'INFO'
        
        for vuln in vulnerabilities:
            sev = vuln.get('severity', 'INFO')
            score = RiskScoringEngine.get_severity_score(sev)
            total_score += score
            
            if score > RiskScoringEngine.get_severity_score(highest_severity):
                highest_severity = sev
                
        # The overall risk is represented by the highest severity found
        return highest_severity, total_score
