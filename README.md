# netcat-openbsd
openbsd netcat with debian and other patches

See _changelog_ for details.
## Project layout
__master__ tracks unpatched OpenBSD sources.
<br>
For every OpenBSD update, there is a branch named after the CVS revision of
__netcat.c__. Should an update not change the CVS revision,
the branch name will have a suffix: -2, -3 and so on.
<br>
Similarly, the  branch name will update if a debian patch changes.
