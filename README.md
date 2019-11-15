# AppImageBuilder

A recipe based AppImage creation meta-tool featuring:

__Done__:
- Structured recipes
- AppImage creation in modern system (backward compatibility is keep) 
- all-in bundles (no external dependencies but Linux Kernel and libfuse)
- distributions compatibility testing
- Assisted licensing compliance

__Todo__:
- Embed software tracking
- AppDir structure validation
- Reproducible builds*
- continuous integration ready

__Limitations__:
- only Debian based systems are supported as build platform. _If you think
we should support another please let us know._

# Features description

## Structured recipes

Recipes are wrote using the `yaml` format resulting in a well 
structured and human readable recipe were each build step is
specified in a different section.

User can check the `examples` folder for already built recipes. 

## AppImage creation in modern system

Building an AppImage in a modern system using the traditional methods
renders to bundles incompatible with any distribution released before
due glib and glibc missing features.

AppImageBuilder fixes this issue by embedding those libraries and the
required loader tool making your bundle __really__ self-sufficient.

## all-in bundles

All goes into the resulting AppImage file. And by all we also mean
libc, glib, libssl and any other library. This may render having
outdated bundles a security issue. But bundles can be easily 
rebuilt by user or developers so it just takes an update.

A draw-back of this feature is that the resulting AppImage have a
larger size, yet it's about ~10 mb which _is not a big deal in
modern times_.


## distributions compatibility testing

Compatibility tests can be easily setup to run the resulting
bundle in different distributions by means of docker. Therefore
developers can have a real idea of where they software will be
able to run.


## Embed software tracking

As the bundle is built using the packages from the host system 
package manager it's possible to store the exact list of which
software was embed and it's version. By retriving this information
security tools can detect if there are vulnerabilities reported
for such versions and warn the users about it.

## AppDir structure validation

To check whether the AppDir is properly formed and there are no
missing resources.

## Reproducible builds

Recipes can be embed in the resulting bundle so users can recreate
the package without major efforts and compare the results.

## Assisted licensing compliance

The host system package manager already include the licenses of
every software piece therefore this information is also passed
into the resulting bundle.

## continuous integration ready

Provide hooks to publish the resulting bundle into the different
applications stores or binary hosting services.