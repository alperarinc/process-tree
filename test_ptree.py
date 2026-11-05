import unittest
import unittest.mock

from ptree import build_rows, read_procs


def P(pid, ppid, cmd):
    return dict(pid=pid, ppid=ppid, user="u", cpu=0.0, mem=0.0, rss=0, cmd=cmd)


PROCS = {p["pid"]: p for p in [P(0, 0, "kernel_task"), P(1, 0, "launchd"), P(10, 1, "/bin/zsh"),
                               P(11, 10, "/usr/bin/vim"), P(20, 1, "Finder")]}


class BuildRows(unittest.TestCase):
    def pids(self, rows):
        return [p["pid"] for _, p in rows]

    def test_tree_order_and_prefix(self):
        rows = build_rows(PROCS)
        self.assertEqual(self.pids(rows), [0, 1, 10, 11, 20])
        self.assertTrue(rows[3][0].endswith("└─  "))  # vim: leaf, last child

    def test_collapse_hides_children(self):
        self.assertEqual(self.pids(build_rows(PROCS, collapsed={10})), [0, 1, 10, 20])

    def test_filter_keeps_ancestors(self):
        self.assertEqual(self.pids(build_rows(PROCS, query="VIM")), [0, 1, 10, 11])
        self.assertEqual(self.pids(build_rows(PROCS, query="20")), [0, 1, 20])

    def test_live_ps_every_process_shown_once(self):
        procs = read_procs()
        pids = self.pids(build_rows(procs))
        self.assertEqual(sorted(pids), sorted(procs))


class ReadProcs(unittest.TestCase):
    def test_turkish_locale_decimal_comma(self):
        # tr_TR'de ps "3,7" yazar; read_procs locale'den bağımsız olmalı
        with unittest.mock.patch.dict("os.environ", {"LC_ALL": "tr_TR.UTF-8", "LANG": "tr_TR.UTF-8"}):
            self.assertTrue(read_procs())


if __name__ == "__main__":
    unittest.main()
