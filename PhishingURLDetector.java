import java.net.URL;
import java.util.*;
import java.util.regex.*;

public class PhishingURLDetector {

    // Sample blacklist
    static Set<String> blacklist = new HashSet<>(Arrays.asList(
            "malicious.com",
            "phishing.net",
            "badsite.org",
            "fakebank.com"
    ));

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter URL: ");
        String inputURL = scanner.nextLine();

        analyzeURL(inputURL);

        scanner.close();
    }

    public static void analyzeURL(String url) {
        int riskScore = 0;

        System.out.println("\n--- URL Analysis Report ---");

        // 1. Check if URL is valid
        if (!isValidURL(url)) {
            System.out.println("❌ Invalid URL format!");
            return;
        } else {
            System.out.println("✅ Valid URL format");
        }

        // 2. Extract domain
        String domain = getDomain(url);
        System.out.println("🌐 Domain: " + domain);

        // 3. Blacklist check
        if (blacklist.contains(domain)) {
            System.out.println("🚨 Blacklisted URL detected!");
            riskScore += 50;
        } else {
            System.out.println("✅ Not in blacklist");
        }

        // 4. URL length check
        if (url.length() > 75) {
            System.out.println("⚠️ Suspicious: URL too long");
            riskScore += 10;
        }

        // 5. Check for IP address instead of domain
        if (containsIPAddress(url)) {
            System.out.println("⚠️ Suspicious: Contains IP address");
            riskScore += 20;
        }

        // 6. Check for '@' symbol
        if (url.contains("@")) {
            System.out.println("⚠️ Suspicious: Contains '@' symbol");
            riskScore += 15;
        }

        // 7. Check for multiple subdomains
        if (countDots(domain) > 3) {
            System.out.println("⚠️ Suspicious: Too many subdomains");
            riskScore += 10;
        }

        // 8. Check for HTTPS
        if (!url.toLowerCase().startsWith("https://")) {
            System.out.println("⚠️ Not secure (HTTP used)");
            riskScore += 10;
        } else {
            System.out.println("🔒 Secure (HTTPS)");
        }

        // 9. Special characters check
        if (containsSpecialChars(url)) {
            System.out.println("⚠️ Suspicious: Special characters detected");
            riskScore += 5;
        }

        // Final Score
        System.out.println("\n📊 Risk Score: " + riskScore);

        // Classification
        if (riskScore >= 60) {
            System.out.println("🚨 Result: PHISHING URL");
        } else if (riskScore >= 30) {
            System.out.println("⚠️ Result: SUSPICIOUS URL");
        } else {
            System.out.println("✅ Result: SAFE URL");
        }
    }

    // Validate URL
    public static boolean isValidURL(String url) {
        try {
            URL u = new URL(url);

            // Only allow HTTP and HTTPS
            String protocol = u.getProtocol();

            return protocol.equalsIgnoreCase("http")
                    || protocol.equalsIgnoreCase("https");

        } catch (Exception e) {
            return false;
        }
    }

    // Extract domain
    public static String getDomain(String url) {
        try {
            URL u = new URL(url);
            return u.getHost().toLowerCase();
        } catch (Exception e) {
            return "";
        }
    }

    // Check for IP address
    public static boolean containsIPAddress(String url) {
        String ipPattern =
                "((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}"
                + "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";

        Pattern pattern = Pattern.compile(ipPattern);
        Matcher matcher = pattern.matcher(url);

        return matcher.find();
    }

    // Count dots
    public static int countDots(String domain) {
        int count = 0;

        for (char c : domain.toCharArray()) {
            if (c == '.') {
                count++;
            }
        }

        return count;
    }

    // Check special characters
    public static boolean containsSpecialChars(String url) {
        return url.matches(".*[<>\"{}|\\\\^`].*");
    }
};