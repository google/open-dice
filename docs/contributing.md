# Contributing

We'd love to accept your patches and contributions to this project. There are
just a few small guidelines you need to follow.

## Contributor License Agreement

Contributions to this project must be accompanied by a Contributor License
Agreement. You (or your employer) retain the copyright to your contribution;
this simply gives us permission to use and redistribute your contributions as
part of the project. Head over to <https://cla.developers.google.com/> to see
your current agreements on file or to sign a new one.

You generally only need to submit a CLA once, so if you've already submitted one
(even if it was for a different project), you probably don't need to do it
again.

## Code Reviews

All submissions, including submissions by project members, require review. We
use Gerrit for this purpose, we do not currently support GitHub pull requests.

See the
[Gerrit walkthrough](https://gerrit-review.googlesource.com/Documentation/intro-gerrit-walkthrough.html),
[Gerrit user guide](https://gerrit-review.googlesource.com/Documentation/intro-user.html)
and other
[Gerrit documentation](https://gerrit-review.googlesource.com/Documentation/index.html)
for more information. GitHub users may find the
[walkthrough for GitHub users](https://gerrit-review.googlesource.com/Documentation/intro-gerrit-walkthrough-github.html)
helpful.

### Gerrit Commit Hook

Set up the
[Gerrit commit hook](https://gerrit-review.googlesource.com/tools/hooks/commit-msg)
to automatically add a `Change-Id` tag to each commit. On Linux you can run:

```bash
$ f=`git rev-parse --git-dir`/hooks/commit-msg ; mkdir -p $(dirname $f) ; curl -Lo $f https://gerrit-review.googlesource.com/tools/hooks/commit-msg ; chmod +x $f
```

## Community Guidelines

This project follows
[Google's Open Source Community Guidelines](https://opensource.google/conduct/).

## Source Code Headers

Every file containing source code must include copyright and license
information.

Apache header for C and C++ files:

```javascript
// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.
```

Apache header for Python and GN files:

```python
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
```
