<?php
/**
 * contact.php — Script de traitement du formulaire de contact RBK Groupe
 * -------------------------------------------------------------------------
 * Sécurité : Honeypot anti-bot, validation checkbox humain, sanitization XSS,
 * validation email serveur, envoi via PHPMailer (SMTP ou mail() natif).
 *
 * Réponse : JSON { status: "success"|"error", message: "..." }
 * -------------------------------------------------------------------------
 */

declare(strict_types=1);

// --- En-têtes de sécurité ---
header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');

// --- Uniquement les requêtes POST AJAX ---
if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($_SERVER['HTTP_X_REQUESTED_WITH'])) {
    http_response_code(405);
    echo json_encode(['status' => 'error', 'message' => 'Méthode non autorisée.']);
    exit;
}

// =====================================================================
// ÉTAPE 1 — HONEYPOT ANTI-BOT
// Si le champ caché est rempli, c'est un robot. On simule un succès.
// =====================================================================
$honeypot = $_POST['username_verification'] ?? '';
if (!empty($honeypot)) {
    // On leurre le bot : réponse de succès sans envoyer d'email
    echo json_encode(['status' => 'success', 'message' => 'Message envoyé.']);
    exit;
}

// =====================================================================
// ÉTAPE 2 — VALIDATION CHECKBOX "HUMAIN + RGPD"
// =====================================================================
$human = $_POST['human_validate'] ?? '';
if ($human !== '1') {
    http_response_code(400);
    echo json_encode([
        'status'  => 'error',
        'message' => 'Veuillez cocher la case de validation humaine et RGPD.'
    ]);
    exit;
}

// =====================================================================
// ÉTAPE 3 — NETTOYAGE ET VALIDATION DES DONNÉES
// =====================================================================

/**
 * Sanitize une chaîne : supprime les espaces superflus, encode les entités HTML.
 */
function sanitize(string $value): string
{
    return htmlspecialchars(strip_tags(trim($value)), ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

$nom     = sanitize($_POST['nom'] ?? '');
$prenom  = sanitize($_POST['prenom'] ?? '');
$email   = filter_var(trim($_POST['email'] ?? ''), FILTER_SANITIZE_EMAIL);
$message = sanitize($_POST['message'] ?? '');
$subject = sanitize($_POST['subject'] ?? 'Contact général');

// Vérifications serveur
$errors = [];

if (strlen($nom) < 2) {
    $errors[] = 'Le nom est invalide (minimum 2 caractères).';
}

if (strlen($prenom) < 2) {
    $errors[] = 'Le prénom est invalide (minimum 2 caractères).';
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errors[] = 'L\'adresse e-mail fournie est invalide.';
}

if (strlen($message) < 10) {
    $errors[] = 'Le message est trop court (minimum 10 caractères).';
}

if (!empty($errors)) {
    http_response_code(422);
    echo json_encode([
        'status'  => 'error',
        'message' => implode(' ', $errors)
    ]);
    exit;
}

// =====================================================================
// ÉTAPE 4 — ENVOI PAR PHPMAILER
// =====================================================================

// Chargement de PHPMailer
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

require_once __DIR__ . '/lib/PHPMailer/Exception.php';
require_once __DIR__ . '/lib/PHPMailer/PHPMailer.php';
require_once __DIR__ . '/lib/PHPMailer/SMTP.php';

// -----------------------------------------------
// CONFIGURATION — Remplacez les valeurs ci-dessous
// -----------------------------------------------
define('MAIL_TO',         'contact@rbk-groupe.fr');   // ← Votre adresse de réception
define('MAIL_FROM',       'noreply@rbk-groupe.fr');    // ← Expéditeur (doit appartenir à votre domaine)
define('MAIL_FROM_NAME',  'RBK Groupe – Formulaire Contact');

// SMTP (recommandé — décommentez et renseignez si votre hébergeur supporte SMTP)
define('USE_SMTP',        false);   // true = SMTP, false = mail() natif hébergeur
define('SMTP_HOST',       'smtp.monhebergeur.fr');   // Ex : smtp.ionos.fr, ssl0.ovh.net
define('SMTP_PORT',       587);                       // 587 (TLS) ou 465 (SSL) ou 25
define('SMTP_SECURE',     PHPMailer::ENCRYPTION_STARTTLS); // STARTTLS ou SMTPS
define('SMTP_USERNAME',   'noreply@rbk-groupe.fr');
define('SMTP_PASSWORD',   'VOTRE_MOT_DE_PASSE_SMTP'); // ← À remplacer
// -----------------------------------------------

$mail = new PHPMailer(true);

try {
    // Configuration de base
    $mail->CharSet   = 'UTF-8';
    $mail->Encoding  = 'base64';
    $mail->XMailer   = ' '; // Cache le mailer

    if (USE_SMTP) {
        // Mode SMTP
        $mail->isSMTP();
        $mail->Host       = SMTP_HOST;
        $mail->Port       = SMTP_PORT;
        $mail->SMTPAuth   = true;
        $mail->SMTPSecure = SMTP_SECURE;
        $mail->Username   = SMTP_USERNAME;
        $mail->Password   = SMTP_PASSWORD;
        // $mail->SMTPDebug = SMTP::DEBUG_SERVER; // Décommenter pour déboguer
    } else {
        // Mode mail() natif (partagé hébergeur)
        $mail->isMail();
    }

    // Expéditeur & destinataire
    $mail->setFrom(MAIL_FROM, MAIL_FROM_NAME);
    $mail->addAddress(MAIL_TO, 'RBK Groupe');

    // Reply-to : permet de répondre directement au client
    $mail->addReplyTo($email, $prenom . ' ' . $nom);

    // Objet
    $subjectLine = '[RBK Contact] ' . ($subject ?: 'Nouvelle demande') . ' – ' . $prenom . ' ' . $nom;
    $mail->Subject = $subjectLine;

    // Corps HTML
    $htmlBody = buildEmailHtml($nom, $prenom, $email, $subject, $message);
    $mail->isHTML(true);
    $mail->Body    = $htmlBody;
    $mail->AltBody = buildEmailText($nom, $prenom, $email, $subject, $message);

    $mail->send();

    // =====================================================================
    // ÉTAPE 5 — RÉPONSE JSON SUCCÈS
    // =====================================================================
    echo json_encode([
        'status'  => 'success',
        'message' => 'Votre message a été envoyé avec succès.'
    ]);

} catch (Exception $e) {
    error_log('[RBK Contact] Erreur PHPMailer : ' . $mail->ErrorInfo);
    http_response_code(500);
    echo json_encode([
        'status'  => 'error',
        'message' => 'Une erreur technique est survenue lors de l\'envoi. Veuillez nous contacter directement par téléphone.'
    ]);
}

// =====================================================================
// HELPERS — Génération du corps de l'email
// =====================================================================

function buildEmailHtml(string $nom, string $prenom, string $email, string $subject, string $message): string
{
    $messageHtml = nl2br(htmlspecialchars($message, ENT_QUOTES | ENT_HTML5, 'UTF-8'));
    $date        = date('d/m/Y à H:i');

    return <<<HTML
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Nouveau message – RBK Groupe</title>
</head>
<body style="margin:0;padding:0;background:#0a0a0a;font-family:'Segoe UI',Helvetica,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0a0a;padding:40px 20px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background:#111;border:1px solid #222;border-radius:16px;overflow:hidden;max-width:600px;">

          <!-- En-tête -->
          <tr>
            <td style="background:linear-gradient(135deg,#1a0505 0%,#111 100%);padding:28px 36px;border-bottom:1px solid #1e1e1e;">
              <h1 style="margin:0;font-size:22px;font-weight:800;color:#fff;letter-spacing:-0.3px;">
                📬 Nouveau message
                <span style="color:#e11a1a;">RBK Groupe</span>
              </h1>
              <p style="margin:6px 0 0;font-size:13px;color:#666;">{$date}</p>
            </td>
          </tr>

          <!-- Sujet -->
          <tr>
            <td style="padding:20px 36px 0;">
              <span style="display:inline-block;background:rgba(225,26,26,0.12);border:1px solid rgba(225,26,26,0.25);color:#f87171;font-size:12px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;border-radius:50px;padding:5px 14px;">
                {$subject}
              </span>
            </td>
          </tr>

          <!-- Identité -->
          <tr>
            <td style="padding:20px 36px 0;">
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td width="48%" style="background:#1a1a1a;border:1px solid #252525;border-radius:10px;padding:14px 16px;">
                    <p style="margin:0;font-size:11px;color:#555;text-transform:uppercase;letter-spacing:1.5px;font-weight:600;">Prénom</p>
                    <p style="margin:4px 0 0;font-size:16px;font-weight:700;color:#fff;">{$prenom}</p>
                  </td>
                  <td width="4%"></td>
                  <td width="48%" style="background:#1a1a1a;border:1px solid #252525;border-radius:10px;padding:14px 16px;">
                    <p style="margin:0;font-size:11px;color:#555;text-transform:uppercase;letter-spacing:1.5px;font-weight:600;">Nom</p>
                    <p style="margin:4px 0 0;font-size:16px;font-weight:700;color:#fff;">{$nom}</p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Email -->
          <tr>
            <td style="padding:12px 36px 0;">
              <div style="background:#1a1a1a;border:1px solid #252525;border-radius:10px;padding:14px 16px;">
                <p style="margin:0;font-size:11px;color:#555;text-transform:uppercase;letter-spacing:1.5px;font-weight:600;">Adresse e-mail</p>
                <a href="mailto:{$email}" style="display:inline-block;margin:4px 0 0;font-size:15px;font-weight:600;color:#e11a1a;text-decoration:none;">{$email}</a>
              </div>
            </td>
          </tr>

          <!-- Message -->
          <tr>
            <td style="padding:16px 36px 0;">
              <div style="background:#0d0d0d;border:1px solid #252525;border-radius:10px;padding:18px 20px;">
                <p style="margin:0 0 10px;font-size:11px;color:#555;text-transform:uppercase;letter-spacing:1.5px;font-weight:600;">Message</p>
                <p style="margin:0;font-size:15px;color:#ccc;line-height:1.7;">{$messageHtml}</p>
              </div>
            </td>
          </tr>

          <!-- Action -->
          <tr>
            <td style="padding:24px 36px 32px;">
              <a href="mailto:{$email}?subject=Re: {$subject}"
                 style="display:inline-block;background:#e11a1a;color:#fff;font-size:14px;font-weight:700;text-decoration:none;border-radius:10px;padding:12px 24px;">
                ↩ Répondre à {$prenom}
              </a>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="border-top:1px solid #1e1e1e;padding:18px 36px;text-align:center;">
              <p style="margin:0;font-size:12px;color:#444;">
                Ce message a été envoyé via le formulaire de contact du site <strong style="color:#666;">rbk-groupe.fr</strong><br>
                IP : {$_SERVER['REMOTE_ADDR']} — Heure serveur : {$date}
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
HTML;
}

function buildEmailText(string $nom, string $prenom, string $email, string $subject, string $message): string
{
    $date = date('d/m/Y à H:i');
    return <<<TEXT
Nouveau message via le formulaire de contact RBK Groupe
========================================================
Date    : {$date}
Sujet   : {$subject}
Prénom  : {$prenom}
Nom     : {$nom}
Email   : {$email}

Message :
---------
{$message}

---
Envoyé depuis rbk-groupe.fr | IP : {$_SERVER['REMOTE_ADDR']}
TEXT;
}
