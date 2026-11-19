//! Estimation de la force d'un mot de passe (zxcvbn) avec conseils en français.

/// Longueur minimale recommandée.
pub const MIN_RECOMMENDED_LEN: usize = 12;

/// Longueur maximale analysée (zxcvbn est coûteux sur de très longues entrées).
const MAX_ANALYZED_CHARS: usize = 100;

/// Résultat de l'évaluation d'un mot de passe. Ne contient aucune copie du mot de passe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Strength {
    /// Score de 0 (très faible) à 4 (très fort).
    pub score: u8,
    /// Libellé en français.
    pub label: &'static str,
    /// Vrai si le mot de passe est jugé insuffisant.
    pub weak: bool,
    /// Conseils d'amélioration.
    pub hints: Vec<&'static str>,
}

/// Évalue la force d'un mot de passe.
pub fn evaluate(password: &str) -> Strength {
    let len = password.chars().count();
    let analyzed: String = password.chars().take(MAX_ANALYZED_CHARS).collect();
    let mut score = u8::from(zxcvbn::zxcvbn(&analyzed, &[]).score());
    drop(zeroize::Zeroizing::new(analyzed));
    if len < MIN_RECOMMENDED_LEN {
        score = score.min(2);
    }
    let classes = [
        password.chars().any(|c| c.is_lowercase()),
        password.chars().any(|c| c.is_uppercase()),
        password.chars().any(|c| c.is_ascii_digit()),
        password.chars().any(|c| !c.is_alphanumeric()),
    ]
    .iter()
    .filter(|&&b| b)
    .count();

    let mut hints = Vec::new();
    if len < MIN_RECOMMENDED_LEN {
        hints.push(
            "Utilisez au moins 12 caractères, idéalement une phrase de passe de 5 ou 6 mots.",
        );
    }
    if classes < 3 && score < 4 {
        hints.push("Mélangez minuscules, majuscules, chiffres et symboles.");
    }
    if score < 3 && len >= MIN_RECOMMENDED_LEN {
        hints.push("Évitez les mots courants, les dates, les noms et les suites (azerty, 1234…).");
    }

    let label = match score {
        0 => "Très faible",
        1 => "Faible",
        2 => "Moyen",
        3 => "Fort",
        _ => "Très fort",
    };
    Strength {
        score,
        label,
        weak: score < 3,
        hints,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mots_de_passe_faibles() {
        for p in ["", "1234", "motdepasse", "azertyuiop", "Password1!"] {
            assert!(evaluate(p).weak, "{p:?} devrait être faible");
        }
        assert!(!evaluate("").hints.is_empty());
    }

    #[test]
    fn phrase_de_passe_forte() {
        let s = evaluate("cheval-agrafe-Lune-violon-27-orage");
        assert!(!s.weak);
        assert!(s.score >= 3);
    }

    #[test]
    fn court_jamais_fort() {
        assert!(evaluate("Xq7#pL2!").weak);
    }

    #[test]
    fn tres_long_ne_bloque_pas() {
        let long = "a".repeat(10_000);
        let _ = evaluate(&long);
    }
}
