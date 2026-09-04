// Registers the ab_testing feature flag without enabling it for anyone.
//
// Run against prod from a machine with the Mongo URI:
//   mongosh "$MONGODB_URI/url-shortener" scripts/seed_ab_testing_flag.js
//
// Idempotent: only inserts when no doc exists, so a flag a human has
// already edited (allowlist, rollout) is never rewritten. Add accounts
// afterwards with:
//   db.feature_flags.updateOne({name: "ab_testing"},
//     {$addToSet: {allowlist_emails: "someone@example.com"}})
// and unregister with:
//   db.feature_flags.deleteOne({name: "ab_testing"})
// The app picks changes up within the flag cache TTL (about 30s).

const now = new Date();
const result = db.feature_flags.updateOne(
  { name: "ab_testing" },
  {
    $setOnInsert: {
      name: "ab_testing",
      enabled: true,
      rollout_type: "allowlist",
      allowlist_user_ids: [],
      allowlist_emails: [],
      percentage: 0,
      enabled_digits: [],
      tier: null,
      description:
        "A/B split destinations (ab_variants). Allowlist until paid plans gate it by tier.",
      created_at: now,
      updated_at: now,
    },
  },
  { upsert: true },
);

const doc = db.feature_flags.findOne({ name: "ab_testing" });
print(result.upsertedCount ? "inserted ab_testing flag" : "ab_testing flag already registered, untouched");
printjson({
  enabled: doc.enabled,
  rollout_type: doc.rollout_type,
  allowlist_emails: doc.allowlist_emails,
  created_at: doc.created_at,
});
