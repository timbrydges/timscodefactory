"""Feature planning: budget-sized splitting and safe dependency ordering."""
import copy
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from factory_runtime import task_intake, task_plan  # noqa: E402

HELPER = {
    'idea_id': 'reading-time-helper',
    'objective': 'Compute an estimated reading time.',
    'requirements': ['Add readingMinutes(words) in src/lib/reading-time.ts.'],
    'allowed_paths': ['src/lib/reading-time.ts', 'tests/reading-time.test.mjs'],
    'builder_test': 'tests/reading-time.test.mjs',
    'acceptance': [{'type': 'returns', 'module': 'src/lib/reading-time.ts', 'function': 'readingMinutes',
                    'args': [450], 'expect': 3}],
}
BADGE = {
    'idea_id': 'reading-time-badge',
    'objective': 'Show the reading time on each library card.',
    'requirements': ['Render the minutes from readingMinutes on each card in library-browser.tsx.'],
    'allowed_paths': ['src/app/dashboard/library-browser.tsx', 'tests/reading-badge.test.mjs'],
    'builder_test': 'tests/reading-badge.test.mjs',
    'source_file_bytes': {'src/app/dashboard/library-browser.tsx': 9000},
    'acceptance': [{'type': 'source_contains', 'path': 'src/app/dashboard/library-browser.tsx',
                    'text': 'readingMinutes('}],
    'depends_on': ['reading-time-helper'],
}
SORT = {
    'idea_id': 'reading-time-sort',
    'objective': 'Allow sorting by reading time.',
    'requirements': ['Add a "Shortest read" option to the sort menu.'],
    'allowed_paths': ['src/app/dashboard/library-browser.tsx', 'tests/reading-sort.test.mjs'],
    'builder_test': 'tests/reading-sort.test.mjs',
    'source_file_bytes': {'src/app/dashboard/library-browser.tsx': 9000},
    'acceptance': [{'type': 'source_contains', 'path': 'src/app/dashboard/library-browser.tsx',
                    'text': 'Shortest read'}],
}
# One idea far too large for a single attempt: a new module plus two big existing files.
BIG = {
    'idea_id': 'reading-dashboard',
    'objective': 'Reading statistics on the dashboard.',
    'requirements': ['Add stats helpers, a stats panel and wire it into the page.'],
    'allowed_paths': ['src/app/dashboard/page.tsx', 'src/app/dashboard/stats-panel.tsx',
                      'src/lib/reading-stats.ts', 'tests/reading-stats.test.mjs'],
    'builder_test': 'tests/reading-stats.test.mjs',
    'source_file_bytes': {'src/app/dashboard/page.tsx': 30000, 'src/app/dashboard/stats-panel.tsx': 14000},
    'acceptance': [
        {'type': 'exports', 'module': 'src/lib/reading-stats.ts', 'names': ['totalMinutes']},
        {'type': 'source_contains', 'path': 'src/app/dashboard/stats-panel.tsx', 'text': 'totalMinutes('},
        {'type': 'source_contains', 'path': 'src/app/dashboard/page.tsx', 'text': '<StatsPanel'},
    ],
}


def feature(*ideas):
    return {'feature_id': 'reading-time', 'repository': 'timbrydges/bonus-library',
            'ideas': [copy.deepcopy(i) for i in ideas]}


class PlanTests(unittest.TestCase):
    def test_multi_part_feature_orders_dependencies_and_shared_files(self):
        # Listed out of order: the badge needs the helper, and the sort shares the badge's file.
        result = task_plan.plan(feature(BADGE, SORT, HELPER))
        self.assertEqual(result['order'], ['reading-time-helper', 'reading-time-badge', 'reading-time-sort'])
        tasks = {t['idea_id']: t for t in result['tasks']}
        self.assertEqual(tasks['reading-time-sort']['depends_on'], ['reading-time-badge'])
        self.assertTrue(all(t['input_class'] == 'standard' for t in result['tasks']))
        self.assertTrue(all('target_commit' not in t for t in result['tasks']))

    def test_oversized_idea_is_split_library_first_wiring_last(self):
        self.assertIsNone(task_plan.input_class(dict(BIG, repository='r', **task_plan.PLACEHOLDER)))
        result = task_plan.plan(feature(BIG))
        self.assertGreater(len(result['tasks']), 1)
        for task in result['tasks']:
            self.assertIn(task['input_class'], ('standard', 'large'))
            self.assertLessEqual(task_plan.estimated_request_bytes(
                dict(task, **task_plan.PLACEHOLDER)), task_plan.LIMITS[task['input_class']])
            self.assertTrue(task['acceptance'])
        first, last = result['tasks'][0], result['tasks'][-1]
        self.assertIn('src/lib/reading-stats.ts', first['allowed_paths'])
        self.assertIn('src/app/dashboard/page.tsx', last['allowed_paths'])
        for earlier, later in zip(result['tasks'], result['tasks'][1:]):
            self.assertIn(earlier['idea_id'], later['depends_on'])
        files = [p for t in result['tasks'] for p in t['allowed_paths'] if not p.startswith('tests/')]
        self.assertEqual(sorted(files), sorted(p for p in BIG['allowed_paths'] if not p.startswith('tests/')))

    def test_dependency_on_a_split_idea_waits_for_its_last_part(self):
        after = dict(copy.deepcopy(HELPER), idea_id='after-dashboard', depends_on=['reading-dashboard'])
        result = task_plan.plan(feature(BIG, after))
        last = [t['idea_id'] for t in result['tasks'] if t['idea_id'].startswith('reading-dashboard')][-1]
        self.assertEqual(result['order'][-1], 'after-dashboard')
        self.assertIn(last, {t['idea_id']: t for t in result['tasks']}['after-dashboard']['depends_on'])

    def test_cycles_unknown_dependencies_and_unsplittable_ideas_fail_closed(self):
        a = dict(copy.deepcopy(HELPER), depends_on=['reading-time-badge'])
        with self.assertRaises(task_plan.PlanError):
            task_plan.plan(feature(a, BADGE))
        with self.assertRaises(task_plan.PlanError):
            task_plan.plan(feature(dict(copy.deepcopy(HELPER), depends_on=['missing-task'])))
        huge = dict(copy.deepcopy(BADGE), source_file_bytes={'src/app/dashboard/library-browser.tsx': 200000},
                    depends_on=[])
        with self.assertRaises(task_plan.PlanError):
            task_plan.plan(feature(huge))
        no_criteria = dict(copy.deepcopy(BIG), acceptance=BIG['acceptance'][:1])
        with self.assertRaises(task_plan.PlanError):
            task_plan.plan(feature(no_criteria))

    def test_next_ready_releases_tasks_as_dependencies_merge_and_drafts_cleanly(self):
        result = task_plan.plan(feature(BADGE, SORT, HELPER))
        pins = dict(main_commit='a' * 40, manifest_digest='sha256:' + 'b' * 64)
        ready = task_plan.next_ready(result, merged=set(), **pins)
        self.assertEqual([i['idea_id'] for i in ready], ['reading-time-helper'])
        ready = task_plan.next_ready(result, merged={'reading-time-helper'}, **pins)
        self.assertEqual([i['idea_id'] for i in ready], ['reading-time-badge'])
        record = task_intake.draft(ready[0])
        self.assertEqual(record['status'], 'PENDING_APPROVAL')
        self.assertEqual(record['task']['target_commit'], 'a' * 40)
        self.assertEqual(record['task']['depends_on'], ['reading-time-helper'])
        self.assertEqual(task_plan.next_ready(result, merged={'reading-time-helper', 'reading-time-badge',
                                                              'reading-time-sort'}, **pins), [])


if __name__ == '__main__':
    unittest.main()
