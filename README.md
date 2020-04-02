# netcat-openbsd
openbsd netcat with debian and other patches

See _changelog_ for details.
## Project layout
__master__ tracks unpatched OpenBSD sources.
<br>
For every OpenBSD update, there is a branch named after the CVS revision of
__netcat.c__ with a suffix of -1 Should an update not change the CVS revision,
the branch name will have a suffix: -2, -3 and so on.
<br>
Similarly,
a new branch is created with an updated suffix
on accepting a debian patch change.
## Release names
Release names are suffixed CVS revisions like branch names.
The suffix increments on any non-OpenBSD change.
As such, it bears no relation to the branch name suffix.
