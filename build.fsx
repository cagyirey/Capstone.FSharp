#I @"packages/build/FAKE/tools"
#r @"FakeLib.dll"

open Fake
open Fake.AssemblyInfoFile
open Fake.ReleaseNotesHelper
open Fake.Testing

open System
open System.IO

type Project = 
    { Name: string
      Summary: string
      Guid: string }

let solutionName = "Capstone.FSharp"

let configuration = "Release"

let tags = "capstone, x86, disassembler"

let mainProject = 
    { Name = solutionName
      Summary = "Capstone Engine language bindings for F#."
      Guid = "8b18e4e0-376d-4aa8-86ac-4ded5a56305c" }

let releaseNotes = ReleaseNotesHelper.parseReleaseNotes (File.ReadLines "RELEASE_NOTES.md")

let solutionFile = solutionName + ".sln"

// publishable projects - for generated lib info
let projects = [ mainProject ]

let buildDir = "./bin"
let outputDir = buildDir @@ configuration

let testAssemblies = "bin/**/*Tests*.dll"

let isAppveyorBuild = (environVar >> isNotNullOrEmpty) "APPVEYOR" 
let appveyorBuildVersion = sprintf "%s-a%s" releaseNotes.AssemblyVersion (DateTime.UtcNow.ToString "yyMMddHHmm")

let mergeBinaries = false

Target "Clean" (fun () ->
    CleanDirs [buildDir]
)

Target "AppveyorBuildVersion" (fun () ->
    Shell.Exec("appveyor", sprintf "UpdateBuild -Version \"%s\"" appveyorBuildVersion) |> ignore
)

Target "AssemblyInfo" (fun () ->
    List.iter(fun project -> 
        let filename = "./src" @@ project.Name @@ "AssemblyInfo.fs"
        CreateFSharpAssemblyInfo filename
            [ Attribute.Title project.Name
              Attribute.Product solutionName
              Attribute.Description project.Summary
              Attribute.Version releaseNotes.AssemblyVersion
              Attribute.FileVersion releaseNotes.AssemblyVersion
              Attribute.Guid project.Guid ]) projects
)

Target "CopyLicense" (fun _ ->
    [ "LICENSE.md" ]
    |> CopyTo (outputDir)
)

Target "Build" (fun _ ->
    !! solutionFile
    |> MSBuildRelease outputDir "Rebuild"
    |> ignore
)

Target "ILMerge" (fun _ -> 
    let ilmergePath = "./packages/build/ilmerge/tools/ilmerge.exe"
    let targetBinary = solutionName + ".dll"
    let mergedLibs = 
        Directory.GetFiles(outputDir, "*.dll")
        |> Set.ofArray
        |> Set.remove (outputDir @@ targetBinary)

    let mergeFolder = Directory.CreateDirectory (buildDir @@ "merged")
    ILMerge 
        (fun p -> 
            { p with 
                ToolPath = ilmergePath
                Libraries = mergedLibs
                AllowDuplicateTypes = AllowDuplicateTypes.AllPublicTypes
        })
        (mergeFolder.FullName @@ targetBinary)
        (Path.GetFullPath <| outputDir @@ targetBinary)
)

Target "RunTests" (fun _ ->
    !! testAssemblies
    |> NUnit3 (fun p ->
        { p with
            WorkingDir = Path.GetFullPath (outputDir)
            ShadowCopy = false
            TimeOut = TimeSpan.FromMinutes 10. })
)

Target "All" DoNothing

"Clean"
    =?> ("AppveyorBuildVersion", isAppveyorBuild)
    ==> "AssemblyInfo"
    ==> "CopyLicense"
    ==> "Build"
    =?>("ILMerge", mergeBinaries)
    ==> "RunTests"
    ==> "All"

let target = getBuildParamOrDefault "target" "All"

RunTargetOrDefault target