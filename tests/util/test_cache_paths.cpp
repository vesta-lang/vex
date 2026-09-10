/*
 * VestaVM -- Maquina Virtual Distribuida
 *
 * Copyright (C) 2026 David Lopez.T (DesmonHak) (Castilla y Leon, ES)
 * Licencia: GPLv2 + excepcion de runtime (ver LICENSE).
 */

/**
 * @file test_cache_paths.cpp
 * @brief The cache layout must stay a layout: one root, one drawer per kind,
 *        and a declared scope for each.  See util/cache_paths.h.
 *
 * What is checked here is not that the code runs.  It is that the table cannot
 * rot without somebody noticing, because every way it can rot is silent:
 *
 *   two kinds sharing a drawer   artefacts of one type land among another's,
 *                                and purging one takes the other with it.
 *   a drawer with a path in it   the name is a leaf, not a route; a separator
 *                                would let a kind escape its root.
 *   a wrong scope                somebody copies the portable half to another
 *                                machine and takes absolute paths along.
 *
 * Written entirely in English on purpose: a test has no message catalogue, so
 * nothing here is ever shown to a user in their own language.
 */

#include "util/cache_paths.h"

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <set>
#include <string>
#include <system_error>

namespace fs = std::filesystem;

static int g_checks = 0;
static int g_fail = 0;
#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        ++g_checks;                                                            \
        if (!(cond)) {                                                         \
            ++g_fail;                                                          \
            std::printf("  FAIL: %s (line %d)\n", (msg), __LINE__);            \
        }                                                                      \
    } while (0)

/**
 * @brief Does @p text end with @p suffix?
 *
 * @param text   Haystack.
 * @param suffix What it should end with.
 * @return true when it does.
 */
static bool ends_with(const std::string &text, const std::string &suffix) {
    if (suffix.size() > text.size()) return false;
    return text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}

/**
 * @brief The root name is what every other document is written against.
 */
static void test_the_root_is_called_dot_cache() {
    CHECK(std::strcmp(util::cache_root_name(), ".cache") == 0,
          "the root is called .cache");
}

/**
 * @brief Every kind names a drawer, and no two kinds name the same one.
 *
 * A shared drawer is not a cosmetic problem: purging one type would take the
 * other with it, and the two would be indistinguishable inside.
 */
static void test_drawer_names_are_unique_leaves() {
    std::set<std::string> seen;
    for (size_t i = 0; i < util::kCacheKindCount; ++i) {
        const util::CacheKind kind = static_cast<util::CacheKind>(i);
        const char *dir = util::cache_kind_dir(kind);
        CHECK(dir != nullptr, "every kind names a drawer");
        if (dir == nullptr) continue;
        const std::string name(dir);
        CHECK(!name.empty(), "the drawer name is not empty");
        /* A leaf, not a route.  A separator here would let a kind climb out of
         * the root, and the whole point of the root is that deleting it is
         * enough.  The debug graph is the one exception: it splits packs from
         * roots inside itself because their scopes differ. */
        const bool nested_is_allowed = (kind == util::CacheKind::DebugInfo);
        CHECK(nested_is_allowed || name.find('/') == std::string::npos,
              "the drawer name is a leaf, not a path");
        CHECK(name.find("..") == std::string::npos,
              "the drawer name cannot climb out of the root");
        CHECK(seen.insert(name).second, "two kinds share a drawer");
    }
    CHECK(seen.size() == util::kCacheKindCount,
          "as many drawers as there are kinds");
}

/**
 * @brief Every kind declares a scope, and the scope has a name to report with.
 */
static void test_every_kind_declares_a_scope() {
    for (size_t i = 0; i < util::kCacheKindCount; ++i) {
        const util::CacheKind kind = static_cast<util::CacheKind>(i);
        const util::CacheScope scope = util::cache_kind_scope(kind);
        const bool known = scope == util::CacheScope::Portable ||
                           scope == util::CacheScope::Local ||
                           scope == util::CacheScope::Transient ||
                           scope == util::CacheScope::Mixed;
        CHECK(known, "the scope is one of the declared ones");
        const char *name = util::cache_scope_name(scope);
        CHECK(name != nullptr && name[0] != 0, "the scope has a name");
    }
}

/**
 * @brief The scopes a tool would act on, pinned one by one.
 *
 * These are the ones somebody archives, shares or deletes without looking, so
 * getting one wrong is the difference between copying a compiled interface and
 * copying a list of absolute paths from another machine.
 */
static void test_the_scopes_that_matter_are_pinned() {
    CHECK(util::cache_kind_scope(util::CacheKind::ModuleIr) ==
              util::CacheScope::Portable,
          "the module interface and IR travel");
    CHECK(util::cache_kind_scope(util::CacheKind::Facts) ==
              util::CacheScope::Portable,
          "what the ASA knew travels");
    CHECK(util::cache_kind_scope(util::CacheKind::Bytecode) ==
              util::CacheScope::Portable,
          "compiled bytecode travels when the target matches");
    CHECK(util::cache_kind_scope(util::CacheKind::Projects) ==
              util::CacheScope::Local,
          "the project cache holds absolute paths and does NOT travel");
    CHECK(util::cache_kind_scope(util::CacheKind::Temp) ==
              util::CacheScope::Transient,
          "write temporaries are throwaway");
    CHECK(util::cache_kind_scope(util::CacheKind::DebugInfo) ==
              util::CacheScope::Mixed,
          "the debug graph splits: packs travel, roots do not");
}

/**
 * @brief Every drawer hangs from the root, and from nowhere else.
 */
static void test_drawers_hang_from_the_root() {
    const std::string &root = util::cache_root();
    CHECK(!root.empty(), "the root is never empty");
    for (size_t i = 0; i < util::kCacheKindCount; ++i) {
        const util::CacheKind kind = static_cast<util::CacheKind>(i);
        const std::string dir = util::cache_dir(kind);
        CHECK(dir.size() > root.size(), "the drawer is under the root");
        CHECK(dir.compare(0, root.size(), root) == 0,
              "the drawer starts at the root");
        CHECK(ends_with(dir, util::cache_kind_dir(kind)),
              "the drawer ends with its own name");
    }
}

/**
 * @brief A drawer under somebody else's root, for whoever brings their own.
 */
static void test_drawer_under_a_given_root() {
    const std::string dir =
        util::cache_dir_under("some/where", util::CacheKind::Packages);
    CHECK(!dir.empty(), "a given root produces a path");
    CHECK(dir.find(util::cache_root_name()) != std::string::npos,
          "the root name is inserted");
    CHECK(ends_with(dir, util::cache_kind_dir(util::CacheKind::Packages)),
          "it ends with the drawer name");
    /* No root means no path -- NOT a path relative to wherever we happen to
     * be.  Falling back would write somebody's packages into the working
     * directory, which is the kind of default that never errors and always
     * surprises. */
    CHECK(util::cache_dir_under(std::string(), util::CacheKind::Packages)
              .empty(),
          "an empty root yields an empty path, not a relative one");
}

/**
 * @brief A kind outside the table must be visible, never a crash.
 */
static void test_a_kind_outside_the_table_is_survivable() {
    const util::CacheKind bogus =
        static_cast<util::CacheKind>(util::kCacheKindCount + 7);
    const char *dir = util::cache_kind_dir(bogus);
    CHECK(dir != nullptr && dir[0] != 0,
          "an unknown kind still names something");
    CHECK(!util::cache_dir(bogus).empty(),
          "an unknown kind still yields a path");
}

/**
 * @brief Builds a throwaway tree to walk upwards through.
 *
 * @param leaf Receives the deepest directory created.
 * @return The root of the throwaway tree, or empty if it could not be made.
 */
static std::string make_probe_tree(std::string &leaf) {
    std::error_code ec;
    const fs::path base =
        fs::temp_directory_path(ec) / "vesta_cache_paths_probe";
    if (ec) return std::string();
    fs::remove_all(base, ec);
    const fs::path deep = base / "pkg" / "sub" / "deeper";
    fs::create_directories(deep, ec);
    if (ec) return std::string();
    leaf = deep.string();
    return base.string();
}

/**
 * @brief Writes an empty file, so a marker exists without any content.
 *
 * @param path Where.
 */
static void touch_marker(const fs::path &path) {
    std::FILE *f = std::fopen(path.string().c_str(), "wb");
    if (f != nullptr) std::fclose(f);
}

/**
 * @brief Only a package manifest counts as a package root.
 *
 * The package manager needs this to be strict: a working copy of a version
 * control system is not a package, and treating it as one would have it
 * install into a directory that declares nothing.
 */
static void test_package_root_needs_a_manifest() {
    std::string leaf;
    const std::string base = make_probe_tree(leaf);
    if (base.empty()) {
        std::printf("  SKIP: could not create the probe tree\n");
        return;
    }
    std::error_code ec;
    const fs::path pkg = fs::path(base) / "pkg";

    // Nothing declared yet: this directory is not a package root.
    const std::string none = util::project_root_from(leaf);
    CHECK(fs::path(none) != pkg, "without a manifest there is no root here");

    // A manifest two levels up IS the package root.
    touch_marker(pkg / "vx.toml");
    const std::string found = util::project_root_from(leaf);
    CHECK(fs::path(found) == pkg, "the manifest two levels up is the root");

    fs::remove_all(base, ec);
}

/**
 * @brief The cache also accepts the root of a working copy.
 *
 * This is the marker that keeps a tree from sprouting one cache per directory:
 * most places the compiler is invoked from are not packages.
 */
static void test_tree_root_also_accepts_a_working_copy() {
    std::string leaf;
    const std::string base = make_probe_tree(leaf);
    if (base.empty()) {
        std::printf("  SKIP: could not create the probe tree\n");
        return;
    }
    std::error_code ec;
    const fs::path pkg = fs::path(base) / "pkg";

    fs::create_directories(fs::path(base) / ".git", ec);
    const std::string tree = util::tree_root_from(leaf);
    CHECK(fs::path(tree) == fs::path(base),
          "the working copy root is found when no package is nearer");

    /* A package NEARER than the working copy wins: it is a unit of its own, so
     * its cache belongs to it. */
    touch_marker(pkg / "vx.toml");
    const std::string nearer = util::tree_root_from(leaf);
    CHECK(fs::path(nearer) == pkg, "a nearer package wins over the tree root");

    /* The package manager, on the other hand, must NOT see the working copy:
     * that is the whole difference between the two functions. */
    fs::remove(pkg / "vx.toml", ec);
    const std::string pkg_only = util::project_root_from(leaf);
    CHECK(fs::path(pkg_only) != fs::path(base),
          "a working copy is not a package");

    fs::remove_all(base, ec);
}

int main() {
    test_the_root_is_called_dot_cache();
    test_drawer_names_are_unique_leaves();
    test_every_kind_declares_a_scope();
    test_the_scopes_that_matter_are_pinned();
    test_drawers_hang_from_the_root();
    test_drawer_under_a_given_root();
    test_a_kind_outside_the_table_is_survivable();
    test_package_root_needs_a_manifest();
    test_tree_root_also_accepts_a_working_copy();

    std::printf("=== cache paths: %d checks, %d failures ===\n", g_checks,
                g_fail);
    return g_fail == 0 ? 0 : 1;
}
