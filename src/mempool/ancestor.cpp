// Copyright (c) 2024-2026 The FTC Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "mempool/ancestor.h"

#include "core/logging.h"
#include "core/types.h"
#include "mempool/entry.h"
#include "mempool/policy.h"

#include <algorithm>
#include <cstddef>
#include <deque>
#include <functional>
#include <string>
#include <unordered_set>
#include <vector>

namespace mempool {

// ---------------------------------------------------------------------------
// add_entry
// ---------------------------------------------------------------------------

void AncestorTracker::add_entry(
    const core::uint256& txid,
    const std::vector<core::uint256>& parents) {

    // Initialize the parent set for this transaction.
    Uint256Set& parent_set = parents_[txid];
    for (const auto& parent : parents) {
        // Only add parents that are actually tracked (in the mempool).
        if (parents_.count(parent) > 0 || children_.count(parent) > 0) {
            parent_set.insert(parent);
        }
    }

    // Ensure this txid has a children entry (even if empty).
    if (children_.find(txid) == children_.end()) {
        children_[txid] = Uint256Set{};
    }

    // Register this txid as a child of each parent.
    for (const auto& parent : parent_set) {
        children_[parent].insert(txid);
    }

    LOG_DEBUG(core::LogCategory::MEMPOOL,
        "ancestor tracker: added " + txid.to_hex()
        + " with " + std::to_string(parent_set.size()) + " parents");
}

// ---------------------------------------------------------------------------
// remove_entry
// ---------------------------------------------------------------------------

void AncestorTracker::remove_entry(const core::uint256& txid) {
    // Remove this txid from the children set of each of its parents.
    auto pit = parents_.find(txid);
    if (pit != parents_.end()) {
        for (const auto& parent : pit->second) {
            auto cit = children_.find(parent);
            if (cit != children_.end()) {
                cit->second.erase(txid);
            }
        }
        parents_.erase(pit);
    }

    // Remove this txid from the parent set of each of its children.
    auto cit = children_.find(txid);
    if (cit != children_.end()) {
        for (const auto& child : cit->second) {
            auto cpit = parents_.find(child);
            if (cpit != parents_.end()) {
                cpit->second.erase(txid);
            }
        }
        children_.erase(cit);
    }

    LOG_DEBUG(core::LogCategory::MEMPOOL,
        "ancestor tracker: removed " + txid.to_hex());
}

// ---------------------------------------------------------------------------
// clear
// ---------------------------------------------------------------------------

void AncestorTracker::clear() {
    parents_.clear();
    children_.clear();
}

// ---------------------------------------------------------------------------
// BFS walk (generic helper)
// ---------------------------------------------------------------------------

Uint256Set AncestorTracker::bfs_walk(
    const core::uint256& txid,
    const std::unordered_map<core::uint256, Uint256Set, Uint256Hash>& adj)
    const {

    Uint256Set visited;
    std::deque<core::uint256> queue;

    visited.insert(txid);
    queue.push_back(txid);

    while (!queue.empty()) {
        core::uint256 current = queue.front();
        queue.pop_front();

        auto it = adj.find(current);
        if (it != adj.end()) {
            for (const auto& neighbor : it->second) {
                if (visited.insert(neighbor).second) {
                    queue.push_back(neighbor);
                }
            }
        }
    }

    return visited;
}

// ---------------------------------------------------------------------------
// get_ancestors / get_descendants
// ---------------------------------------------------------------------------

std::vector<core::uint256>
AncestorTracker::get_ancestors(const core::uint256& txid) const {
    Uint256Set visited = bfs_walk(txid, parents_);
    return std::vector<core::uint256>(visited.begin(), visited.end());
}

std::vector<core::uint256>
AncestorTracker::get_descendants(const core::uint256& txid) const {
    Uint256Set visited = bfs_walk(txid, children_);
    return std::vector<core::uint256>(visited.begin(), visited.end());
}

// ---------------------------------------------------------------------------
// get_parents / get_children
// ---------------------------------------------------------------------------

std::vector<core::uint256>
AncestorTracker::get_parents(const core::uint256& txid) const {
    auto it = parents_.find(txid);
    if (it == parents_.end()) {
        return {};
    }
    return std::vector<core::uint256>(it->second.begin(), it->second.end());
}

std::vector<core::uint256>
AncestorTracker::get_children(const core::uint256& txid) const {
    auto it = children_.find(txid);
    if (it == children_.end()) {
        return {};
    }
    return std::vector<core::uint256>(it->second.begin(), it->second.end());
}

// ---------------------------------------------------------------------------
// count_ancestors / count_descendants
// ---------------------------------------------------------------------------

size_t AncestorTracker::count_ancestors(const core::uint256& txid) const {
    Uint256Set visited = bfs_walk(txid, parents_);
    return visited.size();
}

size_t AncestorTracker::count_descendants(const core::uint256& txid) const {
    Uint256Set visited = bfs_walk(txid, children_);
    return visited.size();
}

// ---------------------------------------------------------------------------
// has_entry / size
// ---------------------------------------------------------------------------

bool AncestorTracker::has_entry(const core::uint256& txid) const {
    return parents_.count(txid) > 0;
}

size_t AncestorTracker::size() const {
    return parents_.size();
}

// ---------------------------------------------------------------------------
// update_ancestor_state
// ---------------------------------------------------------------------------

void AncestorTracker::update_ancestor_state(
    MempoolEntry& entry,
    const std::function<const MempoolEntry*(const core::uint256&)>& lookup)
    const {

    Uint256Set ancestors = bfs_walk(entry.txid, parents_);

    size_t count = 0;
    size_t total_vsize = 0;
    int64_t total_fees = 0;

    for (const auto& anc_txid : ancestors) {
        const MempoolEntry* anc = lookup(anc_txid);
        if (anc != nullptr) {
            ++count;
            total_vsize += anc->vsize;
            total_fees += anc->fee.value();
        }
    }

    entry.ancestor_count = count;
    entry.ancestor_size  = total_vsize;
    entry.ancestor_fees  = primitives::Amount{total_fees};
}

// ---------------------------------------------------------------------------
// update_descendant_state
// ---------------------------------------------------------------------------

void AncestorTracker::update_descendant_state(
    MempoolEntry& entry,
    const std::function<const MempoolEntry*(const core::uint256&)>& lookup)
    const {

    Uint256Set descendants = bfs_walk(entry.txid, children_);

    size_t count = 0;
    size_t total_vsize = 0;
    int64_t total_fees = 0;

    for (const auto& desc_txid : descendants) {
        const MempoolEntry* desc = lookup(desc_txid);
        if (desc != nullptr) {
            ++count;
            total_vsize += desc->vsize;
            total_fees += desc->fee.value();
        }
    }

    entry.descendant_count = count;
    entry.descendant_size  = total_vsize;
    entry.descendant_fees  = primitives::Amount{total_fees};
}

// ---------------------------------------------------------------------------
// recalculate_affected
// ---------------------------------------------------------------------------

void AncestorTracker::recalculate_affected(
    const core::uint256& txid,
    const std::function<const MempoolEntry*(const core::uint256&)>& lookup,
    const std::function<void(MempoolEntry&)>& update) const {

    // When a transaction is added or removed, the ancestor/descendant state
    // of its ancestors and descendants may have changed. We need to
    // recalculate for all affected entries.
    //
    // Affected set = ancestors(txid) union descendants(txid).
    // For each affected entry, recompute both ancestor and descendant state.

    Uint256Set affected;

    // Gather ancestors (walk parents).
    {
        Uint256Set ancs = bfs_walk(txid, parents_);
        affected.insert(ancs.begin(), ancs.end());
    }

    // Gather descendants (walk children).
    {
        Uint256Set descs = bfs_walk(txid, children_);
        affected.insert(descs.begin(), descs.end());
    }

    // For each affected entry, recalculate ancestor and descendant state.
    for (const auto& affected_txid : affected) {
        const MempoolEntry* entry_ptr = lookup(affected_txid);
        if (entry_ptr == nullptr) {
            continue;
        }

        // We need a mutable reference. The update callback is expected to
        // provide it.
        MempoolEntry updated = *entry_ptr;

        // Recalculate ancestor state.
        {
            Uint256Set ancs = bfs_walk(affected_txid, parents_);
            size_t count = 0;
            size_t total_vsize = 0;
            int64_t total_fees = 0;
            for (const auto& a : ancs) {
                const MempoolEntry* ae = lookup(a);
                if (ae != nullptr) {
                    ++count;
                    total_vsize += ae->vsize;
                    total_fees += ae->fee.value();
                }
            }
            updated.ancestor_count = count;
            updated.ancestor_size  = total_vsize;
            updated.ancestor_fees  = primitives::Amount{total_fees};
        }

        // Recalculate descendant state.
        {
            Uint256Set descs = bfs_walk(affected_txid, children_);
            size_t count = 0;
            size_t total_vsize = 0;
            int64_t total_fees = 0;
            for (const auto& d : descs) {
                const MempoolEntry* de = lookup(d);
                if (de != nullptr) {
                    ++count;
                    total_vsize += de->vsize;
                    total_fees += de->fee.value();
                }
            }
            updated.descendant_count = count;
            updated.descendant_size  = total_vsize;
            updated.descendant_fees  = primitives::Amount{total_fees};
        }

        update(updated);
    }
}

// ---------------------------------------------------------------------------
// check_limits
// ---------------------------------------------------------------------------

bool AncestorTracker::check_limits(
    const core::uint256& txid,
    const std::vector<core::uint256>& parents,
    size_t own_vsize,
    size_t max_ancestors,
    size_t max_descendants,
    size_t max_ancestor_size,
    size_t max_descendant_size,
    const std::function<const MempoolEntry*(const core::uint256&)>& lookup,
    std::string& reason) const {

    // --- Compute hypothetical ancestor set ---
    // The ancestor set is the union of the ancestor sets of all parents,
    // plus self.
    Uint256Set ancestor_set;
    ancestor_set.insert(txid);

    for (const auto& parent : parents) {
        // Add the parent itself.
        ancestor_set.insert(parent);

        // Add all ancestors of the parent.
        Uint256Set parent_ancs = bfs_walk(parent, parents_);
        ancestor_set.insert(parent_ancs.begin(), parent_ancs.end());
    }

    // Check ancestor count (including self).
    if (ancestor_set.size() > max_ancestors) {
        reason = "too many unconfirmed ancestors: "
               + std::to_string(ancestor_set.size())
               + " > limit " + std::to_string(max_ancestors);
        return false;
    }

    // Check ancestor size.
    size_t ancestor_vsize = own_vsize;
    for (const auto& anc_txid : ancestor_set) {
        if (anc_txid == txid) continue; // already counted own_vsize
        const MempoolEntry* anc = lookup(anc_txid);
        if (anc != nullptr) {
            ancestor_vsize += anc->vsize;
        }
    }
    if (ancestor_vsize > max_ancestor_size) {
        reason = "exceeds ancestor size limit: "
               + std::to_string(ancestor_vsize) + " vB > limit "
               + std::to_string(max_ancestor_size) + " vB";
        return false;
    }

    // --- Check descendant limits of each parent ---
    // Adding this transaction increases the descendant count of every
    // ancestor by 1. We need to check that no ancestor exceeds the
    // descendant limit.
    for (const auto& anc_txid : ancestor_set) {
        if (anc_txid == txid) continue;

        const MempoolEntry* anc = lookup(anc_txid);
        if (anc == nullptr) continue;

        // The new descendant count for this ancestor would be its current
        // descendant count + 1 (for the new transaction).
        size_t new_desc_count = anc->descendant_count + 1;
        if (new_desc_count > max_descendants) {
            reason = "too many descendants for ancestor "
                   + anc_txid.to_hex() + ": "
                   + std::to_string(new_desc_count) + " > limit "
                   + std::to_string(max_descendants);
            return false;
        }

        // Check descendant size.
        size_t new_desc_size = anc->descendant_size + own_vsize;
        if (new_desc_size > max_descendant_size) {
            reason = "exceeds descendant size limit for ancestor "
                   + anc_txid.to_hex() + ": "
                   + std::to_string(new_desc_size) + " vB > limit "
                   + std::to_string(max_descendant_size) + " vB";
            return false;
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// check_package_limits (simplified wrapper)
// ---------------------------------------------------------------------------

bool AncestorTracker::check_package_limits(
    const core::uint256& txid,
    const std::vector<core::uint256>& parents,
    size_t own_vsize,
    const std::function<const MempoolEntry*(const core::uint256&)>& lookup,
    std::string& reason) const {

    return check_limits(
        txid, parents, own_vsize,
        MAX_ANCESTORS, MAX_DESCENDANTS,
        MAX_ANCESTOR_SIZE, MAX_DESCENDANT_SIZE,
        lookup, reason);
}

// ---------------------------------------------------------------------------
// topological_sort (all entries)
// ---------------------------------------------------------------------------

std::vector<core::uint256> AncestorTracker::topological_sort() const {
    // Collect all tracked txids.
    std::vector<core::uint256> all_txids;
    all_txids.reserve(parents_.size());
    for (const auto& [txid, pset] : parents_) {
        all_txids.push_back(txid);
    }
    return topological_sort(all_txids);
}

// ---------------------------------------------------------------------------
// topological_sort (subset)
// ---------------------------------------------------------------------------

std::vector<core::uint256> AncestorTracker::topological_sort(
    const std::vector<core::uint256>& txids) const {

    if (txids.empty()) return {};

    // Build a subset of the parent graph restricted to the given txids.
    Uint256Set id_set(txids.begin(), txids.end());

    // Compute in-degree for each txid within the subset.
    std::unordered_map<core::uint256, size_t, Uint256Hash> in_degree;
    for (const auto& txid : txids) {
        in_degree[txid] = 0;
    }

    for (const auto& txid : txids) {
        auto pit = parents_.find(txid);
        if (pit != parents_.end()) {
            for (const auto& parent : pit->second) {
                if (id_set.count(parent) > 0) {
                    in_degree[txid]++;
                }
            }
        }
    }

    // Kahn's algorithm: start with zero-in-degree nodes.
    std::deque<core::uint256> ready;
    for (const auto& [txid, deg] : in_degree) {
        if (deg == 0) {
            ready.push_back(txid);
        }
    }

    std::vector<core::uint256> sorted;
    sorted.reserve(txids.size());

    while (!ready.empty()) {
        core::uint256 current = ready.front();
        ready.pop_front();
        sorted.push_back(current);

        // For each child of current that is in the subset, decrement in-degree.
        auto cit = children_.find(current);
        if (cit != children_.end()) {
            for (const auto& child : cit->second) {
                if (id_set.count(child) == 0) continue;
                auto dit = in_degree.find(child);
                if (dit != in_degree.end() && dit->second > 0) {
                    dit->second--;
                    if (dit->second == 0) {
                        ready.push_back(child);
                    }
                }
            }
        }
    }

    // If sorted.size() < txids.size(), there was a cycle (should not happen
    // in a valid mempool). Append remaining entries anyway.
    if (sorted.size() < txids.size()) {
        LOG_WARN(core::LogCategory::MEMPOOL,
            "ancestor tracker: topological sort found "
            + std::to_string(txids.size() - sorted.size())
            + " entries in a cycle");
        Uint256Set sorted_set(sorted.begin(), sorted.end());
        for (const auto& txid : txids) {
            if (sorted_set.count(txid) == 0) {
                sorted.push_back(txid);
            }
        }
    }

    return sorted;
}

// ---------------------------------------------------------------------------
// dump
// ---------------------------------------------------------------------------

std::string AncestorTracker::dump() const {
    std::string result;
    result += "AncestorTracker: " + std::to_string(parents_.size())
            + " entries\n";

    for (const auto& [txid, pset] : parents_) {
        result += "  " + txid.to_hex().substr(0, 16) + "...: ";
        result += "parents=[";
        bool first = true;
        for (const auto& parent : pset) {
            if (!first) result += ", ";
            result += parent.to_hex().substr(0, 16) + "...";
            first = false;
        }
        result += "] children=[";
        auto cit = children_.find(txid);
        if (cit != children_.end()) {
            first = true;
            for (const auto& child : cit->second) {
                if (!first) result += ", ";
                result += child.to_hex().substr(0, 16) + "...";
                first = false;
            }
        }
        result += "]\n";
    }

    return result;
}

// ---------------------------------------------------------------------------
// check_consistency
// ---------------------------------------------------------------------------

bool AncestorTracker::check_consistency(std::string& reason) const {
    // For every (txid, parent) in parents_, verify that children_[parent]
    // contains txid.
    for (const auto& [txid, pset] : parents_) {
        for (const auto& parent : pset) {
            auto cit = children_.find(parent);
            if (cit == children_.end()) {
                reason = "parent " + parent.to_hex()
                       + " has no children entry, but is listed as parent of "
                       + txid.to_hex();
                return false;
            }
            if (cit->second.count(txid) == 0) {
                reason = "parent " + parent.to_hex()
                       + " does not list " + txid.to_hex()
                       + " as a child, but parents_ says it should";
                return false;
            }
        }
    }

    // For every (txid, child) in children_, verify that parents_[child]
    // contains txid.
    for (const auto& [txid, cset] : children_) {
        for (const auto& child : cset) {
            auto pit = parents_.find(child);
            if (pit == parents_.end()) {
                reason = "child " + child.to_hex()
                       + " has no parents entry, but is listed as child of "
                       + txid.to_hex();
                return false;
            }
            if (pit->second.count(txid) == 0) {
                reason = "child " + child.to_hex()
                       + " does not list " + txid.to_hex()
                       + " as a parent, but children_ says it should";
                return false;
            }
        }
    }

    // Verify that every txid in parents_ also exists in children_.
    for (const auto& [txid, pset] : parents_) {
        if (children_.count(txid) == 0) {
            reason = txid.to_hex()
                   + " exists in parents_ but not in children_";
            return false;
        }
    }

    // Verify that every txid in children_ also exists in parents_.
    for (const auto& [txid, cset] : children_) {
        if (parents_.count(txid) == 0) {
            reason = txid.to_hex()
                   + " exists in children_ but not in parents_";
            return false;
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// max_depth
// ---------------------------------------------------------------------------

size_t AncestorTracker::max_depth() const {
    size_t max_d = 0;

    for (const auto& [txid, pset] : parents_) {
        // The "depth" of a transaction is the length of its longest
        // ancestor chain. We compute this by BFS from each root.
        Uint256Set ancestors = bfs_walk(txid, parents_);
        if (ancestors.size() > max_d) {
            max_d = ancestors.size();
        }
    }

    return max_d;
}

// ---------------------------------------------------------------------------
// longest_ancestor_chain
// ---------------------------------------------------------------------------

std::vector<core::uint256>
AncestorTracker::longest_ancestor_chain(const core::uint256& txid) const {
    if (parents_.count(txid) == 0) {
        return {};
    }

    // DFS-based longest path finding. Since the DAG is acyclic (enforced
    // by the mempool), we can use DFS without cycle detection.
    //
    // We find the longest path from any root to this txid by recursively
    // finding the parent with the longest chain.

    // Memoization map: txid -> length of longest chain ending at that txid.
    std::unordered_map<core::uint256, size_t, Uint256Hash> memo;

    // Recursive lambda to compute the longest path ending at a given node.
    std::function<size_t(const core::uint256&)> longest_to;
    longest_to = [&](const core::uint256& node) -> size_t {
        auto mit = memo.find(node);
        if (mit != memo.end()) return mit->second;

        size_t best = 1; // Just self.
        auto pit = parents_.find(node);
        if (pit != parents_.end()) {
            for (const auto& parent : pit->second) {
                size_t parent_len = longest_to(parent);
                if (parent_len + 1 > best) {
                    best = parent_len + 1;
                }
            }
        }

        memo[node] = best;
        return best;
    };

    size_t chain_len = longest_to(txid);

    // Now reconstruct the chain by backtracking from txid.
    std::vector<core::uint256> chain;
    chain.reserve(chain_len);
    chain.push_back(txid);

    core::uint256 current = txid;
    for (size_t step = 1; step < chain_len; ++step) {
        auto pit = parents_.find(current);
        if (pit == parents_.end()) break;

        // Pick the parent that gives the longest remaining chain.
        core::uint256 best_parent = current;
        size_t best_len = 0;
        for (const auto& parent : pit->second) {
            size_t plen = memo.count(parent) ? memo[parent] : 0;
            if (plen > best_len) {
                best_len = plen;
                best_parent = parent;
            }
        }
        chain.push_back(best_parent);
        current = best_parent;
    }

    // Reverse so that the root is first.
    std::reverse(chain.begin(), chain.end());
    return chain;
}

// ---------------------------------------------------------------------------
// longest_descendant_chain
// ---------------------------------------------------------------------------

std::vector<core::uint256>
AncestorTracker::longest_descendant_chain(const core::uint256& txid) const {
    if (children_.count(txid) == 0) {
        return {};
    }

    // DFS-based longest path finding from txid following children.
    std::unordered_map<core::uint256, size_t, Uint256Hash> memo;

    std::function<size_t(const core::uint256&)> longest_from;
    longest_from = [&](const core::uint256& node) -> size_t {
        auto mit = memo.find(node);
        if (mit != memo.end()) return mit->second;

        size_t best = 1; // Just self.
        auto cit = children_.find(node);
        if (cit != children_.end()) {
            for (const auto& child : cit->second) {
                size_t child_len = longest_from(child);
                if (child_len + 1 > best) {
                    best = child_len + 1;
                }
            }
        }

        memo[node] = best;
        return best;
    };

    size_t chain_len = longest_from(txid);

    // Reconstruct by following the children greedily.
    std::vector<core::uint256> chain;
    chain.reserve(chain_len);
    chain.push_back(txid);

    core::uint256 current = txid;
    for (size_t step = 1; step < chain_len; ++step) {
        auto cit = children_.find(current);
        if (cit == children_.end()) break;

        core::uint256 best_child = current;
        size_t best_len = 0;
        for (const auto& child : cit->second) {
            size_t clen = memo.count(child) ? memo[child] : 0;
            if (clen > best_len) {
                best_len = clen;
                best_child = child;
            }
        }
        chain.push_back(best_child);
        current = best_child;
    }

    return chain;
}

// ---------------------------------------------------------------------------
// get_roots / get_leaves
// ---------------------------------------------------------------------------

std::vector<core::uint256> AncestorTracker::get_roots() const {
    std::vector<core::uint256> roots;
    for (const auto& [txid, pset] : parents_) {
        if (pset.empty()) {
            roots.push_back(txid);
        }
    }
    return roots;
}

std::vector<core::uint256> AncestorTracker::get_leaves() const {
    std::vector<core::uint256> leaves;
    for (const auto& [txid, cset] : children_) {
        if (cset.empty()) {
            leaves.push_back(txid);
        }
    }
    return leaves;
}

// ---------------------------------------------------------------------------
// depth_of
// ---------------------------------------------------------------------------

size_t AncestorTracker::depth_of(const core::uint256& txid) const {
    if (parents_.count(txid) == 0) {
        return 0;
    }

    // The depth is the length of the longest ancestor chain.
    // We compute it via BFS/DFS over parents.
    std::unordered_map<core::uint256, size_t, Uint256Hash> depth_memo;

    std::function<size_t(const core::uint256&)> compute_depth;
    compute_depth = [&](const core::uint256& node) -> size_t {
        auto mit = depth_memo.find(node);
        if (mit != depth_memo.end()) return mit->second;

        size_t d = 1;
        auto pit = parents_.find(node);
        if (pit != parents_.end()) {
            for (const auto& parent : pit->second) {
                size_t pd = compute_depth(parent);
                if (pd + 1 > d) {
                    d = pd + 1;
                }
            }
        }
        depth_memo[node] = d;
        return d;
    };

    return compute_depth(txid);
}

// ---------------------------------------------------------------------------
// transactions_at_depth
// ---------------------------------------------------------------------------

std::vector<core::uint256>
AncestorTracker::transactions_at_depth(size_t target_depth) const {
    if (target_depth == 0) return {};

    std::vector<core::uint256> result;

    // Compute depth for all transactions.
    std::unordered_map<core::uint256, size_t, Uint256Hash> depth_memo;

    std::function<size_t(const core::uint256&)> compute_depth;
    compute_depth = [&](const core::uint256& node) -> size_t {
        auto mit = depth_memo.find(node);
        if (mit != depth_memo.end()) return mit->second;

        size_t d = 1;
        auto pit = parents_.find(node);
        if (pit != parents_.end()) {
            for (const auto& parent : pit->second) {
                size_t pd = compute_depth(parent);
                if (pd + 1 > d) {
                    d = pd + 1;
                }
            }
        }
        depth_memo[node] = d;
        return d;
    };

    for (const auto& [txid, pset] : parents_) {
        size_t d = compute_depth(txid);
        if (d == target_depth) {
            result.push_back(txid);
        }
    }

    return result;
}

// ---------------------------------------------------------------------------
// connected_component_count / connected_component
// ---------------------------------------------------------------------------

size_t AncestorTracker::connected_component_count() const {
    Uint256Set visited;
    size_t components = 0;

    for (const auto& [txid, pset] : parents_) {
        if (visited.count(txid) > 0) continue;

        // BFS through both parent and child edges.
        std::deque<core::uint256> queue;
        queue.push_back(txid);
        visited.insert(txid);

        while (!queue.empty()) {
            core::uint256 current = queue.front();
            queue.pop_front();

            // Follow parents.
            auto pit = parents_.find(current);
            if (pit != parents_.end()) {
                for (const auto& p : pit->second) {
                    if (visited.insert(p).second) {
                        queue.push_back(p);
                    }
                }
            }

            // Follow children.
            auto cit = children_.find(current);
            if (cit != children_.end()) {
                for (const auto& c : cit->second) {
                    if (visited.insert(c).second) {
                        queue.push_back(c);
                    }
                }
            }
        }

        ++components;
    }

    return components;
}

std::vector<core::uint256>
AncestorTracker::connected_component(const core::uint256& txid) const {
    if (parents_.count(txid) == 0) {
        return {};
    }

    // BFS through both parent and child edges.
    Uint256Set visited;
    std::deque<core::uint256> queue;
    queue.push_back(txid);
    visited.insert(txid);

    while (!queue.empty()) {
        core::uint256 current = queue.front();
        queue.pop_front();

        auto pit = parents_.find(current);
        if (pit != parents_.end()) {
            for (const auto& p : pit->second) {
                if (visited.insert(p).second) {
                    queue.push_back(p);
                }
            }
        }

        auto cit = children_.find(current);
        if (cit != children_.end()) {
            for (const auto& c : cit->second) {
                if (visited.insert(c).second) {
                    queue.push_back(c);
                }
            }
        }
    }

    return std::vector<core::uint256>(visited.begin(), visited.end());
}

// ---------------------------------------------------------------------------
// compute_stats
// ---------------------------------------------------------------------------

AncestorTracker::TrackerStats AncestorTracker::compute_stats() const {
    TrackerStats stats;

    stats.total_entries = parents_.size();

    // Count edges.
    for (const auto& [txid, pset] : parents_) {
        stats.total_parent_edges += pset.size();
    }
    for (const auto& [txid, cset] : children_) {
        stats.total_child_edges += cset.size();
    }

    // Compute per-transaction ancestor/descendant counts.
    for (const auto& [txid, pset] : parents_) {
        size_t anc_count = count_ancestors(txid);
        size_t desc_count = count_descendants(txid);

        if (anc_count > stats.max_ancestor_count) {
            stats.max_ancestor_count = anc_count;
        }
        if (desc_count > stats.max_descendant_count) {
            stats.max_descendant_count = desc_count;
        }
    }

    // Roots and leaves.
    stats.root_count = get_roots().size();
    stats.leaf_count = get_leaves().size();

    // Connected components.
    stats.component_count = connected_component_count();

    // Chain depth.
    stats.max_chain_depth = max_depth();

    // Averages.
    if (stats.total_entries > 0) {
        stats.avg_parents_per_tx =
            static_cast<double>(stats.total_parent_edges)
            / static_cast<double>(stats.total_entries);
        stats.avg_children_per_tx =
            static_cast<double>(stats.total_child_edges)
            / static_cast<double>(stats.total_entries);
    }

    return stats;
}

// ---------------------------------------------------------------------------
// stats_string
// ---------------------------------------------------------------------------

std::string AncestorTracker::stats_string() const {
    TrackerStats stats = compute_stats();
    std::string result;

    result += "AncestorTracker Statistics:\n";
    result += "  entries:           " + std::to_string(stats.total_entries) + "\n";
    result += "  parent edges:      " + std::to_string(stats.total_parent_edges) + "\n";
    result += "  child edges:       " + std::to_string(stats.total_child_edges) + "\n";
    result += "  max ancestors:     " + std::to_string(stats.max_ancestor_count) + "\n";
    result += "  max descendants:   " + std::to_string(stats.max_descendant_count) + "\n";
    result += "  max chain depth:   " + std::to_string(stats.max_chain_depth) + "\n";
    result += "  roots:             " + std::to_string(stats.root_count) + "\n";
    result += "  leaves:            " + std::to_string(stats.leaf_count) + "\n";
    result += "  components:        " + std::to_string(stats.component_count) + "\n";
    result += "  avg parents/tx:    " + std::to_string(stats.avg_parents_per_tx) + "\n";
    result += "  avg children/tx:   " + std::to_string(stats.avg_children_per_tx) + "\n";

    return result;
}

// ---------------------------------------------------------------------------
// remove_entries (batch)
// ---------------------------------------------------------------------------

void AncestorTracker::remove_entries(const std::vector<core::uint256>& txids) {
    // Build a set for quick lookup.
    Uint256Set removal_set(txids.begin(), txids.end());

    // First pass: remove from parent sets of all children.
    for (const auto& txid : txids) {
        auto cit = children_.find(txid);
        if (cit != children_.end()) {
            for (const auto& child : cit->second) {
                if (removal_set.count(child) > 0) continue; // Also being removed.
                auto cpit = parents_.find(child);
                if (cpit != parents_.end()) {
                    cpit->second.erase(txid);
                }
            }
        }
    }

    // Second pass: remove from child sets of all parents.
    for (const auto& txid : txids) {
        auto pit = parents_.find(txid);
        if (pit != parents_.end()) {
            for (const auto& parent : pit->second) {
                if (removal_set.count(parent) > 0) continue; // Also being removed.
                auto pcit = children_.find(parent);
                if (pcit != children_.end()) {
                    pcit->second.erase(txid);
                }
            }
        }
    }

    // Third pass: erase the entries themselves.
    for (const auto& txid : txids) {
        parents_.erase(txid);
        children_.erase(txid);
    }

    if (!txids.empty()) {
        LOG_DEBUG(core::LogCategory::MEMPOOL,
            "ancestor tracker: batch removed " + std::to_string(txids.size())
            + " entries (remaining: " + std::to_string(parents_.size()) + ")");
    }
}

// ---------------------------------------------------------------------------
// check_batch_limits
// ---------------------------------------------------------------------------

bool AncestorTracker::check_batch_limits(
    const std::vector<std::pair<core::uint256,
                                 std::vector<core::uint256>>>& entries,
    const std::function<const MempoolEntry*(const core::uint256&)>& lookup,
    std::string& reason) const {

    // Check each entry individually against the default package limits.
    // Note: this is a conservative check because it doesn't account for
    // the interaction between the new entries (i.e., it checks each entry
    // as if the others aren't being added). A more precise check would
    // simulate adding all entries, but that is more expensive.

    for (const auto& [txid, parents] : entries) {
        const MempoolEntry* entry = lookup(txid);
        size_t own_vsize = 0;
        if (entry != nullptr) {
            own_vsize = entry->vsize;
        }

        std::string entry_reason;
        if (!check_package_limits(txid, parents, own_vsize,
                                   lookup, entry_reason)) {
            reason = "entry " + txid.to_hex() + ": " + entry_reason;
            return false;
        }
    }

    return true;
}

} // namespace mempool
