%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% File: discsthesis.cls, version 3.1, October 10, 2005
%%% Modifications for DISCS thesis format are copyrighted (c) 2005 by
%%% Andrei Coronel, Reena Estuar, JP Vergara and Eric Vidal.  All rights
%%% reserved.
%%%
%%% Please note that most of the instructions below are not valid for this
%%% version.  We will probably need to integrate our changes with the Math
%%% department's template in the future.
%%%
%%% Original copyright notice follows.
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% File: admuthesis.cls, version 3.0, May 11, 2005
%%% ===============================================
%%% Copyright (c) 2005 by Felix Pozon Muga II.  All rights reserved.
%%% =============================================
%%%
%%%
%%% (1) This copyright notice is kept intact on all modified copies.
%%% (2) If you modify this file, you MUST NOT use the original file name.
%%%
%%% This file defines macros used for preparing theses for
%%% Ateneo de Manila University Mathematics Department.
%%% It has been tested with LaTeX2e.
%%% I do NOT guarantee that it will meet all requirements of the
%%% Graduate School; however, if you find that something violates the
%%% specifications, please send me email at <fpmuga@admu.edu.ph> and
%%% I will try to fix it.
%%%
%%% ADMUTHESIS.CLS v3.0 is based on UTTHESIS.STY written by Dinesh Das
%%%
%%% Usage:
%%% ======
%%%
%%% To use this file with LaTeX2e, make sure your TEXINPUTS environment
%%% variable contains the directory in which this file is located.
%%% Include this file as a package in the preamble:
%%%
%%% \documentclass{admuthesis}
%%%
%%% On non-UNIX systems, there might be different environment variables
%%% that might need to be set.  I know nothing about such machines,
%%% however; consult your local guru for details.
%%%
%%% A template for a thesis is provided in the file "admuthesis.tex", available
%%% from the same place where you obtained this file.
%%% Another template "admuthesis2.tex" breaks the thesis into many sub-files.
%%% The subfiles are classified into 3 groups determined by its extension name.
%%% These are: 1. frontmatter files -- "xxx.fmf"
%%%            2. mainmatter files  -- "xxx.mmf"
%%%            3. backmatter files  -- "xxx.bmf"
%%% Frontmatter files are:
%%%           acknowledgement page  -- "acknowledge.fmf"
%%%           abstract page         -- "abstract.fmf"
%%% Mainmatter files are:
%%%           Chapter 1 file        -- "chapter1.mmf"
%%%           Chapter 2 file        -- "chapter2.mmf"
%%%           Chapter 3 file        -- "chapter3.mmf"
%%%             . . .
%%%           Chapter n file        -- "chaptern.mmf"
%%% Backmatter files are:
%%%           Bibliography file     -- "biblio.bmf"
%%%           Appendix 1 file       -- "appendix1.bmf"
%%%           Appendix 2 file       -- "appendix2.bmf"
%%%             . . .
%%%           Appendix n file       -- "appendixn.bmf"
%%%
%%% Command Names:
%%% ==============
%%%
%%% ALL command names used in this file that are used to format the
%%% thesis begin with "thesis" (e.g., \ThesisAuthor).  All of these
%%% commands can be changed by the user using
%%%
%%% \ThesisAuthor{Felix P. Muga II}
%%%
%%% after loading the package in LaTeX2e.
%%%
%%% The following is a list of all thesis-related variables used together
%%% with their default values:
%%%
%%% \UniversityName    %% Name of the University
%%% \ThesisAuthor      %% Name of the author; defaults to "Ako Estudyante".
%%% \DateOfDefense %% Date of Thesis Defense; defaults to "10 May 2005".
%%% \ThesisDefenseYear %% Year of graduation; defaults to "2005".
%%% \ThesisTitle       %% Full title of dissertation; defaults to "Title".
%%% \ThesisAdviser     %% Name of thesis adviser; defaults to "Adviser"
%%% \ThesisType        %% Type of thesis; defaults to "M.S.".
%%% \ThesisDegree      %% Degree for which thesis is submitted; defaults to
%%%                    %% "Master of Science".
%%% \CompreDatesPassed %% Date or Dates the Comprehensive is taken and passed
%%% \ThesisGrade       %% Grade of the Thesis or Dissertation
%%% \SchoolHead        %% Dean of the School
%%% \SchoolHeadPosition      %% Actual Position, either Dean or Acting Dean
%%% \DepartmentName   %% Name of the Department or Program
%%% \DepartmentHead   %% Chair of the Department or Program
%%% \DepartmentHeadPosition     %% Actual Position, either Chair, Acting Chair, or
%%% \FirstPanelMember  %% Thesis/Dissertation Panel Member
%%% \SecondPanelMember %% Thesis/Dissertation Panel Member
%%% \ThirdPanelMember  %% Thesis/Dissertation Panel Member
%%% \FourthPanelMember %% Thesis/Dissertation Panel Member
%%% \ThesisArea        %% The area or field of the thesis. Default is Mathematics
%%%
%%%
%%% In addition to the above variables, the following commands are
%%% provided to generate the optional sections of the thesis:
%%%
%%% \ThesisTitlePage %% Generates the title page.
%%% \ThesisRecommendationPage
%%%                  %% Generates the recommendation for oral defense
%%% \MSThesisAcceptancePage
%%%                  %% Generates the acceptance page signed by the
%%%                  %% MS thesis panel.
%%% \PhDThesisAcceptancePage
%%%                  %% Generates the acceptance page signed by the
%%%                  %% thesis panel.
%%%
%%% There are also a few environments to generate paragraph-like text:
%%%
%%% \thesisacknowledgments
%%%                  %% Text of acknowledgments.
%%% \thesisabstract   %% Text of abstract.
%%%
%%% Bells and Whistles:
%%% ===================
%%%
%%% The following commands are provided purely for playing around with.
%%% They should be used in the document preamble (before \begin{document}).
%%%
%%% \thesisdraft     %% Prints a timestamp at the top of each page.  This
%%%                  %% must be invoked in the document preamble (before
%%%                  %% \begin{document}).
%%% \leftchapter, \centerchapter, \rightchapter
%%%                  %% These commands generate left-justified, centered,
%%%                  %% and right-justified chapter headings, respectively.
%%% \singlespace, \oneandhalfspace, \doublespace
%%%                  %% These define the line spacing to single-space,
%%%                  %% one-and-one-half space, and double-space
%%%                  %% respectively.  Note that the minimum spacing
%%%                  %% required by the Graduate School is \oneandhalfspace,
%%%                  %% but \singlespace is useful, e.g., when using
%%%                  %% \thesisdraft.
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 \NeedsTeXFormat{LaTeX2e}
 \ProvidesClass{discsthesis}[2005/05/11 v3.0 Ateneo de Manila University DISCS Thesis Class]
% \RequirePackage{amsmath,fancyhdr,newcent,curves,epic,eepic,floatfig,epsfig,
 %                amssymb,calc,multicol,array,rotating,tabularx,pifont,fancybox,
  %               ulem,enumerate,latexsym,ifthen}
\RequirePackage[a4paper]{geometry}
\RequirePackage{amsmath,newcent,epsfig,
                amssymb,calc,multicol,array,tabularx,pifont,
                enumerate,latexsym,ifthen}
% packages declared in the tex file should be here
%\RequirePackage{graphicx,multirow,fancyvrb,tabularx,subcaption,lscape,adjustbox,longtable,url}
% \RequirePackage{pgfplots}
%\RequirePackage[titletoc]{appendix}
 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 \newif\if@thdraft{}
 \newcommand\droptnm{final}

 \DeclareOption{draft}{\@thdrafttrue\renewcommand\droptnm{draft}}
 \DeclareOption{final}{\@thdraftfalse\renewcommand\droptnm{final}}
 \DeclareOption*{\PassOptionsToClass{\CurrentOption}{report}}
 \ProcessOptions \LoadClass[12pt]{report}
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 \typeout{*************************************************************}
 \typeout{** ADMU DISCS Thesis Class File, version 3.1, 10 Oct 2005}
 \typeout{** Originally Written by Felix Pozon Muga II }
 \typeout{**                       Mathematics Department }
 \typeout{**                       Ateneo de Manila University }
 \typeout{**                       fmuga@ateneo.edu}
 \typeout{** With modifications by Andrei Coronel, Reena Estuar, }
 \typeout{**                       JP Vergara and Eric Vidal }
 \typeout{*************************************************************}


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Set up page layout parameters.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 \setlength{\textheight}{20.75cm}
 \setlength{\textwidth}{15.5cm}
 \setlength{\oddsidemargin}{0.35in}
 \setlength{\evensidemargin}{0.35in}
 \setlength{\topmargin}{0.0in}
 \setlength{\headheight}{12pt}
 \setlength{\headsep}{20pt}
 \setlength{\parindent}{0.5truein}
 \setlength\headheight{.375truein}%{.
 \setlength\marginparwidth{0pt}
 \setlength\marginparsep{0pt}
 %\setlength\footskip{.375truein}
 \setlength\footskip{0truein}
 \newcommand{\@parindent}{1}
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Set up default values.
 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  \newcommand{\@ThesisTitle}{1}
  \newcommand{\ThesisTitle}[1]{\gdef\@ThesisTitle{#1}}
  \newcommand{\@ThesisAuthor}{1}
  \newcommand{\ThesisAuthor}[1]{\gdef\@ThesisAuthor{#1}}
  \newcommand{\@DefenseDate}{1}
  \newcommand{\DefenseDate}[1]{\gdef\@DefenseDate{#1}}
  \newcommand{\@ThesisDefenseYear}{1}
  \newcommand{\ThesisDefenseYear}[1]{\gdef\@ThesisDefenseYear{#1}}
  \newcommand{\@CompreDatesPassed}{1}
  \newcommand{\CompreDatesPassed}[1]{\gdef\@CompreDatesPassed{#1}}
  \newcommand{\@DepartmentHead}{1}
  \newcommand{\DepartmentHead}[1]{\gdef\@DepartmentHead{#1}}
  \newcommand{\@UniversityName}{1}
  \newcommand{\UniversityName}[1]{\gdef\@UniversityName{#1}}
  \newcommand{\@DepartmentName}{1}
 % \newcommand{\DepartmentName}[1]{\gdef\@DepartmentName{#1}}
  \newcommand{\@DepartmentHeadPosition}{1}
  \newcommand{\DepartmentHeadPosition}[1]{\gdef\@DepartmentHeadPosition{#1}}
  \newcommand{\@ThesisAdviser}{1}
  \newcommand{\ThesisAdviser}[1]{\gdef\@ThesisAdviser{#1}}
  \newcommand{\@SchoolHead}{1}
  \newcommand{\SchoolHead}[1]{\gdef\@SchoolHead{#1}}
  \newcommand{\@SchoolHeadPosition}{1}
  \newcommand{\SchoolHeadPosition}[1]{\gdef\@SchoolHeadPosition{#1}}
  \newcommand{\@SchoolName}{1}
  \newcommand{\SchoolName}[1]{\gdef\@SchoolName{#1}}
  \newcommand{\@FirstPanelMember}{1}
  \newcommand{\FirstPanelMember}[1]{\gdef\@FirstPanelMember{#1}}
  \newcommand{\@SecondPanelMember}{1}
  \newcommand{\SecondPanelMember}[1]{\gdef\@SecondPanelMember{#1}}
  \newcommand{\@ThirdPanelMember}{1}
  \newcommand{\ThirdPanelMember}[1]{\gdef\@ThirdPanelMember{#1}}
  \newcommand{\@FourthPanelMember}{1}
  \newcommand{\FourthPanelMember}[1]{\gdef\@FourthPanelMember{#1}}
  \newcommand{\@ThesisGrade}{1}
  \newcommand{\ThesisGrade}[1]{\gdef\@ThesisGrade{#1}}
  \newcommand{\@ThesisDegree}{1}
  \newcommand{\ThesisDegree}[1]{\gdef\@ThesisDegree{#1}}
  \newcommand{\@ThesisArea}{1}
  \newcommand{\ThesisArea}[1]{\gdef\@ThesisArea{#1}}
  \newcommand{\@ThesisType}{1}
  \newcommand{\ThesisType}[1]{\gdef\@ThesisType{#1}}

 % \ThesisTitle{My paper}
 % \ThesisType{Thesis}
 % \ThesisAuthor{Mr. Author}
  \ThesisDefenseYear{2008}
 % \CompreDatesPassed{March 9,16 and 23, 2001}
  \DepartmentHead{JOHN PAUL C. VERGARA, Ph.D.}
 % \DepartmentName{Department of Information Systems and Computer Science}
  \DepartmentHeadPosition{Chair}
 % \ThesisAdviser{FELIX P. MUGA II, Ph.D.}
  \SchoolHead{FABIAN M. DAYRIT, Ph.D.}
  \SchoolHeadPosition{Dean}
 % \DepartmentName{Department of Information Systems and Computer Science}
  \SchoolName{School of Science and Engineering}
 % \FirstPanelMember{EVANGELINE P. BAUTISTA, Ph.D.}
 % \SecondPanelMember{FELIX P. MUGA II, Ph.D.}
 % \ThirdPanelMember{REGINALDO M. MARCELO, Ph.D.}
 % \FourthPanelMember{JUMELA P. SARMIENTO, Ph.D.}
 % \ThesisGrade{ABOVE AVERAGE}
 % \DefenseDate{May 12, 2005}
  \ThesisDegree{Master of Science}
  \ThesisArea{Computer Science}
  \UniversityName{Ateneo de Manila University}
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 \newcommand{\FrontMatter}{%
  %\addtocontents{toc}{\protect\contentsline{part}{}{\normalsize\textnormal{PAGE}}}
 }
  \newcommand{\MainMatter}{%
  \setlength{\baselineskip}{30pt}
  \addtocontents{toc}{\protect\contentsline{part}{\normalsize\textnormal{CHAPTER}}{}}
  }
  \newcommand{\BackMatter}{%
  \setlength{\baselineskip}{30pt}
  \addtocontents{toc}{\vspace*{-15pt}\protect\contentsline{part}{\normalsize\textnormal{APPENDIX}}{}}
  }

  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  %% Adjusting the Column of MS Approval Sheet
  \newcommand{\@FirstColumnAdjust}{1}
  \newcommand{\FirstColumnAdjust}[1]{\gdef\@FirstColumnAdjust{#1}}
  \newcommand{\@SecondColumnAdjust}{1}
  \newcommand{\SecondColumnAdjust}[1]{\gdef\@SecondColumnAdjust{#1}}

  \FirstColumnAdjust{\hspace*{0pt}}
  \SecondColumnAdjust{\hspace*{0pt}}
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Set up other commands.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 \newcommand{\@defaultbaselinestretch}{1.8}
 \newcommand{\@base}[1]{\renewcommand{\baselinestretch}{#1}}
 \newcommand{\singlespace}{\renewcommand{\@defaultbaselinestretch}{1}}
 \newcommand{\oneandhalfspace}{\renewcommand{\@defaultbaselinestretch}{1.5}}
 \newcommand{\doublespace}{\renewcommand{\@defaultbaselinestretch}{1.8}}
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Command for masters theses.
%%% \phdthesis is provided for symmetry.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 \newcommand{\ThesisStyle}[4]{
  \FirstColumnAdjust{\hspace*{#3}}
  \SecondColumnAdjust{\hspace*{#4}}
   \ifthenelse{\equal{#1}{MS}}
              {\ThesisType{Thesis}
               \ThesisDegree{Master of Science}
               \newcommand{\ThesisDegreeAbbreviation}{M.S.}
               \ifthenelse{\equal{#2}{FinalWithCorner}}
                          {\ThesisTitlePage
                           \ThesisRecommendationPage
                           \MSThesisAcceptancePage}
                          {\ifthenelse{\equal{#2}{Final}}
                                      {\thesisdraft
                                      \ThesisTitlePage
                                      \ThesisRecommendationPage
                                      \MSThesisAcceptancePage
                                      }
                                     {\thesisdraft
                                      \ThesisTitlePage}}
              }
              {\ThesisType{Dissertation}
               \ThesisDegree{Doctor of Philosophy}
               \newcommand{\ThesisDegreeAbbreviation}{Ph.D.}
              \ifthenelse{\equal{#2}{FinalWithCorner}}
              {\ThesisTitlePage
               \ThesisRecommendationPage
               \PhDThesisAcceptancePage}
              {\ifthenelse{\equal{#2}{Final}}
                                      {\thesisdraft
                                      \ThesisTitlePage
                                      \ThesisRecommendationPage
                                      \PhDThesisAcceptancePage
                                      }
                                     {\thesisdraft
                                      \ThesisTitlePage}}
              }
    }%%%%


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Set up default page numbering and line spacing.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 \newcommand{\@textpagenumbering}{arabic}
 \newcommand{\@preamblepagenumbering}{roman}
 \newcommand{\@textpagestyle}{myheadings}
 \newcommand{\@preamblepagestyle}{plain}
 \pagenumbering{\@preamblepagenumbering}
 \@base{\@defaultbaselinestretch}
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  \newcommand{\cornerx}{
   \setlength{\unitlength}{1mm}
   \begin{picture}(0,0)
         \linethickness{2pt}
         \put(-7,7){\path(0,-4)(0,0)(4,0)}
         \put(158,7){\path(-4,0)(0,0)(0,-4)}
         \put(158,-222){\path(-4,0)(0,0)(0,4)}
         \put(-7,-222){\path(0,4)(0,0)(4,0)}
         \put(-20,-100){\begin{sideways}
                        \textsl{Draft of \timestamp}
                        \end{sideways}}
       \end{picture}
}
   \newcommand{\cornerhead}{
   \setlength{\unitlength}{1mm}
   \begin{picture}(0,0)
         % ericvids - fixed so that corners work with pdflatex
         \linethickness{0.3pt}
         \put(-7,7){\line(0,-1){4}}
         \put(-7,7){\line(1,0){4}}
         %{\path(0,-4)(0,0)(4,0)}
         \put(158,7){\line(-1,0){4}}
         \put(158,7){\line(0,-1){4}}
         %{\path(-4,0)(0,0)(0,-4)}
         \put(158,-222){\line(-1,0){4}}
         \put(158,-222){\line(0,1){4}}
         %{\path(-4,0)(0,0)(0,4)}
         \put(-7,-222){\line(0,1){4}}
         \put(-7,-222){\line(1,0){4}}
         %{\path(0,4)(0,0)(4,0)}
       \end{picture}
 }
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 \newcommand{\@chaptertype}{\chaptername}
 \newcommand{\@appendix}{0}
 %%%
 %%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 %%% From File: ltpage.dtx
\def\pagestyle#1{%
  \@ifundefined{ps@#1}%
    \undefinedpagestyle
    {\@nameuse{ps@#1}}}
\def\thispagestyle#1{%
  \@ifundefined{ps@#1}%
    \undefinedpagestyle
    {\global\@specialpagetrue\gdef\@specialstyle{#1}}}
\def\ps@empty{%
  \let\@mkboth\@gobbletwo
  \let\@oddfoot\@empty
  \def\@oddhead{\cornerhead\reset@font\hfil$\;$}
  \let\@evenfoot\@empty
  \let\@evenhead\@oddhead
       }
%%%%%%%%%
\def\ps@myheadings{\let\@mkboth\@gobbletwo
      \let\@oddfoot\@empty
      \def\@oddhead{\cornerhead\reset@font\hfil\thepage}
      \let\@evenfoot\@empty
      \let\@evenhead\@oddhead
     }
%%%%%%%%%
\def\ps@plain{\let\@mkboth\@gobbletwo
  \let\@mkboth\@gobbletwo
  \def\@oddhead{\cornerhead\reset@font\hfil$\;$}
  \def\@oddfoot{\reset@font\hfil\thepage\hfil}
  \let\@evenhead\@oddhead
  \let\@evenfoot\@oddhead
     }
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Command to generate title page.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 \newcommand{\ThesisTitlePage}{

   \pagestyle{empty}
  \begin{center}

%  ATENEO DE MANILA UNIVERSITY

%  \vspace{1cm}

  \textbf{\@ThesisTitle}
%  \vspace{1cm}
  \vfill

%     A THESIS
%
%   PRESENTED TO  THE

%   DEPARTMENT OF INFORMATION SYSTEMS AND COMPUTER SCIENCE

%   ATENEO DE MANILA UNIVERSITY

  A \@ThesisType

 Presented to the

 Department of Information Systems

 and Computer Science

 \@UniversityName

%\vspace{1cm}
\vfill
In Partial Fulfillment

of the Requirements for the Degree% of

Bachelor of Science in Computer Science

 %\vspace{1cm}
 \vfill
 by

%[Full Names of Authors, Format: <FirstName> <M.I.> <LastName>]

%[e.g. Chiara Maria Angelique S. Ledesma
%
% Maria Mikaela E. Jazmines
%
% Leo Isaiah P. Yap III ]
 \@ThesisAuthor

 %\vspace{1cm}

% QUEZON CITY, PHILIPPINES

 \@ThesisDefenseYear
\end{center}
    %$\;$
 \newpage}
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Command to generate recommendation page.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
 \newcommand{\ThesisRecommendationPage}{
  \setlength{\topmargin}{0.0in}
   \pagestyle{\@textpagestyle}

 \paragraph{}The \lowercase\expandafter{\@ThesisType} entitled:


 \begin{center}
 {\@ThesisTitle}
 \end{center}

 \noindent submitted by \@ThesisAuthor{} has been examined and is recommended for Oral Defense.

  \vfill
  \begin{center}
  \begin{tabular}{lcl}
   \@FirstColumnAdjust\shortstack[]{
    \underline{\phantom{\@DepartmentHead}}\\[0pt]
    \@DepartmentHead\\[0pt]
    \@DepartmentHeadPosition\\[0pt]}
   &
   \quad
   &
   \@SecondColumnAdjust\shortstack[]{
    \underline{\phantom{\@ThesisAdviser}}\\[0pt]
    \@ThesisAdviser\\[0pt]
    Adviser\\[0pt]
    % \phantom{ADviser}
    }
 \end{tabular}
 \end{center}

 \vfill

  \begin{center}
 \begin{tabular}{c}
 \shortstack{
 \underline{\phantom{\@SchoolHead}}\\[0pt]
 \@SchoolHead\\[0pt]
 \@SchoolHeadPosition\\[0pt]
 \@SchoolName}
 \end{tabular}
 \end{center}

 \strut\vfill
 %\noindent Comprehensive Examinations Passed \@CompreDatesPassed{}.

 \newpage
  }
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Command to generate acceptance page for MS and MST.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 \newcommand{\MSThesisAcceptancePage}{
    \setlength{\topmargin}{-0.2in}
      \pagestyle{\@textpagestyle}
   The Faculty of the Graduate School of
   \@UniversityName{}\\
   \mbox{accepts} the \lowercase\expandafter{\@ThesisType} entitled:

  \vfill
  \begin{center}
  \textbf{\@ThesisTitle}
  \end{center}

   \vfill
  \noindent submitted by \@ThesisAuthor{} in partial fulfillment of the requirements for the Degree of
  \@ThesisDegree{} in \@ThesisArea.

  \vfill
  \begin{center}
  \begin{tabular}{lll}
   \@FirstColumnAdjust\shortstack{
    \underline{\phantom{\@FirstPanelMember}}\\[0pt]
    \@FirstPanelMember\\[0pt]
    Member}
   &
   \@SecondColumnAdjust\shortstack{
    \underline{\phantom{\@ThesisAdviser}}\\[0pt]
    \@SecondPanelMember\\[0pt]
    Member}\\[28pt]

  \@FirstColumnAdjust\shortstack{
   \underline{\phantom{\@FirstPanelMember}}\\[0pt]
   \@ThirdPanelMember\\[0pt]
   Member
   }
   &
   \@SecondColumnAdjust\shortstack{
   \underline{\phantom{\@ThesisAdviser}}\\[0pt]
   \@ThesisAdviser\\[0pt]
   Adviser
   }
  \end{tabular}
  \end{center}

 \vfill
   \begin{center}
  \begin{tabular}{c}
  \shortstack{
  \underline{\phantom{\@SchoolHead}}\\[0pt]
 \@SchoolHead\\[0pt]
 \@SchoolHeadPosition\\[0pt]
 \@SchoolName}
 \end{tabular}
 \end{center}

 \vfill
 \noindent Grade: \textbf{\@ThesisGrade}\\[8pt]
  Date:$\;\;\;$ \@DefenseDate
\newpage}

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Command to generate acceptance page for PhD.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 \newcommand{\PhDThesisAcceptancePage}{
    \setlength{\topmargin}{0.0in}
    The Faculty of the Graduate School of \@UniversityName\\
    accepts the
    \lowercase\expandafter{\@ThesisType} entitled:

  \begin{center}
  {\@ThesisTitle}
  \end{center}

   \vfill
  \noindent submitted by \@ThesisAuthor{} in partial fulfillment of the requirements for the Degree of
  \@ThesisDegree{} in \@ThesisArea.
  \vfill

   \vfill
   \begin{center}
  \begin{tabular}{lcl}
   \@FirstColumnAdjust\shortstack{
    \underline{\phantom{\@FirstPanelMember}}\\[0pt]
    \@FirstPanelMember\\[0pt]
    Member}
   &
     \quad \;\:
   &
   \@SecondColumnAdjust\shortstack{
    \underline{\phantom{\@SecondPanelMember}}\\[0pt]
    \@SecondPanelMember\\[0pt]
    Member}\\[28pt]

  \@FirstColumnAdjust\shortstack{
   \underline{\phantom{\@ThirdPanelMember}}\\[0pt]
   \@ThirdPanelMember\\[0pt]
   Member
   }
   &
     \quad
   &
   \@SecondColumnAdjust\shortstack{
   \underline{\phantom{\@FourthPanelMember}}\\[0pt]
   \@FourthPanelMember\\[0pt]
   Member
   }
  \end{tabular}
  \end{center}

  \vfill
  \begin{center}
  \begin{tabular}{c}
  \shortstack{
  \underline{\phantom{\@ThesisAdviser}}\\[0pt]
   \@ThesisAdviser\\[0pt]
   Adviser
   }
  \end{tabular}
 \end{center}

 \vfill
  \begin{center}
  \begin{tabular}{c}
  \shortstack{
  \underline{\phantom{\@SchoolHead}}\\[0pt]
 \@SchoolHead\\[0pt]
 \@SchoolHeadPosition\\[0pt]
 \@SchoolName
 }
 \end{tabular}
 \end{center}

 \vfill
 \noindent Grade: {\@ThesisGrade}\\[8pt]
 Date:$\;\;\;$ \@DefenseDate
 \newpage}
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Environment to generate acknowledgments page.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 \newenvironment{acknowledgments}{
  \pagestyle{\@textpagestyle}

  \vspace*{0cm}
     \centerline{\textbf{ACKNOWLEDGMENTS}}
     \addcontentsline{toc}{chapter}{ACKNOWLEDGMENTS}
     %\renewcommand{\parindent}{20pt}
     \vspace*{18pt}
     \renewcommand{\@parindent}{20truein}
     \renewcommand{\@defaultbaselinestretch}{2}
     \begin{spacing}{\@defaultbaselinestretch}}
     %\begin{spacing}{\singlespace}}
     {\end{spacing} \par
      %\strut\vfill
     %\raggedright
     %\@ThesisAuthor, \ThesisDegreeAbbreviation
     %\strut\vfill
     %$\;$
      \newpage}
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Environment to generate abstract page.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 \newenvironment{thesisabstract}{
  \pagestyle{\@textpagestyle}

  \vspace*{-0.5cm}
     \centerline{\textbf{ABSTRACT}}
     \addcontentsline{toc}{chapter}{ABSTRACT}

     \vspace*{18pt}
     \renewcommand{\@defaultbaselinestretch}{2}
     \begin{spacing}{\@defaultbaselinestretch}}
     %\begin{spacing}{\singlespace}}
     {\end{spacing} \par
      %\strut\vfill
     %\raggedright
     %\@ThesisAuthor, \ThesisDegreeAbbreviation
     %\strut\vfill
     %$\;$
      \newpage}
%    \setlength{\topmargin}{0.0in}
%    \pagestyle{empty}
%     \addcontentsline{toc}{chapter}{Abstract}
%     \begin{center}
%       \setlength{\unitlength}{1mm}
%       \begin{spacing}{2}
%       \vspace*{-1.5cm}
%       %{\bfseries \@ThesisTitle} \\[10mm]
%       {\@ThesisTitle} \\[10mm]
%       \end{spacing}
%       \begin{spacing}{1}
%       \@ThesisAuthor, \ThesisDegreeAbbreviation \\
%       \@DepartmentName \\
%       \@SchoolName \\
%       \@UniversityName \\
%       \@DefenseDate\\[6mm]
%       \end{spacing}
%       \lowercase{\@ThesisType} Adviser: \@ThesisAdviser \\
%     \end{center}
%     \vspace{3mm}
%     \renewcommand{\@defaultbaselinestretch}{1}
%     \begin{spacing}{\@defaultbaselinestretch} \noindent}
%     {\end{spacing} \newpage}
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Command from report.cls, (c) LaTeX3 Project.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Environment for Table of Contents
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
 \renewcommand\tableofcontents{%
   \setlength{\baselineskip}{18pt}
    \renewcommand{\contentsname}{TABLE OF CONTENTS}
    \setlength{\topmargin}{0.0in}
    \pagestyle{\@textpagestyle}
    \if@twocolumn
      \@restonecoltrue\onecolumn
    \else
      \@restonecolfalse
    \fi
    \vspace*{0cm}
    \centerline{\textbf{\contentsname}}
    \vspace*{18pt}
    %\chapter*{
    %    \vspace*{-2cm}
    %    {\uppercase{\contentsname}}
    %    \@mkboth{\uppercase{\contentsname}}{\uppercase{\contentsname}}}%
    \@starttoc{toc}%
    \if@restonecol\twocolumn\fi
    \vfill
    \newpage
    }
%%%%
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Environment for List of Tables
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
 \renewcommand{\listtablename}{LIST OF TABLES}
 \renewcommand\listoftables{%
    \setlength{\topmargin}{0.0in}
    \pagestyle{\@textpagestyle}
    \if@twocolumn
      \@restonecoltrue\onecolumn
    \else
      \@restonecolfalse
    \fi
    \vspace*{-1.5cm}
    \centerline{\textbf{\listtablename}}
    \vspace*{18pt}
    %\chapter*{
    % \vspace*{-2cm}
     %{\Large\listtablename}
    % {\listtablename}
    %  \@mkboth{\uppercase{\listtablename}}{\uppercase{\listtablename}}}%
    \addcontentsline{toc}{chapter}{\listtablename}
    \@starttoc{lot}%
    \if@restonecol\twocolumn\fi
    \vfill
    \newpage
    }
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Environment for List of Figures
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
 \renewcommand{\listfigurename}{LIST OF FIGURES}
 \renewcommand\listoffigures{%
    \setlength{\topmargin}{0.0in}
    \pagestyle{\@textpagestyle}
    \if@twocolumn
      \@restonecoltrue\onecolumn
    \else
      \@restonecolfalse
    \fi
    \vspace*{-1.5cm} % originally +1.5cm
    \centerline{\textbf{\listfigurename}}
    \vspace*{18pt}
    %\chapter*{
     %\vspace*{-2cm}
     %{\Large\listfigurename}
     %{\listfigurename}
      %\@mkboth{\uppercase{\listfigurename}}%
      %        {\uppercase{\listfigurename}}}%
    \addcontentsline{toc}{chapter}{\listfigurename}
    \@starttoc{lof}%
    \if@restonecol\twocolumn\fi
    \vfill
    \newpage
    }
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Redefining the chapter command
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 \renewcommand{\thechapter}{\arabic{chapter}}

 \newcommand{\@chapteralignment}{\centering}
 \renewcommand{\chapter}{
   \setlength{\topmargin}{0.0in}
     \renewcommand{\@defaultbaselinestretch}{2}
     \begin{spacing}{\@defaultbaselinestretch}
   \clearpage
   \ifnum\@appendix=1
      \renewcommand{\@chapapp}{\appendixname}%
      \renewcommand{\thechapter}{\Alph{chapter}}
      \renewcommand{\@chaptertype}{\appendixname}
   \else
      \renewcommand{\@chaptertype}{\chaptername}
   \fi
   \thispagestyle{empty}%
   \global\@topnum\z@
   \@afterindentfalse
   \secdef\@chapter\@schapter
   }
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 \renewcommand\appendix{\par
  \setcounter{section}{0}%
   \setlength{\topmargin}{0.0in}
   \clearpage
   \ifnum\@appendix=1
     \renewcommand{\@chapapp}{\appendixname}%
     \renewcommand{\thechapter}{\Alph{chapter}}
     \renewcommand{\@chaptertype}{\appendixname}
   \else
     \setcounter{chapter}{0}
     \renewcommand{\thechapter}{\Alph{chapter}}
     \renewcommand{\@chapapp}{\appendixname}
     \renewcommand{\@chaptertype}{\appendixname}
     \renewcommand{\@appendix}{1}
   \fi
   \thispagestyle{empty}%
   \global\@topnum\z@
   \@afterindentfalse
   \secdef\@chapter\@schapter
   }
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Define chapter heading placement commands.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 \newcommand{\leftchapter}{
    \renewcommand{\@chapteralignment}{\raggedright} }
 \newcommand{\centerchapter}{
    \renewcommand{\@chapteralignment}{\centering}}
 \newcommand{\rightchapter}{
    \renewcommand{\@chapteralignment}{\raggedleft}}

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Command from report.cls, (c) LaTeX3 Project.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 \def\Dotfill{%
  \leavevmode
  \cleaders \hb@xt@ .75em{\hss.\hss}\hfill
  \kern\z@}
 \renewcommand*\l@chapter[2]{%
  \ifnum \c@tocdepth >\m@ne
    \addpenalty{-\@highpenalty}%
    \vskip 1.0em \@plus\p@
    \setlength\@tempdima{1.5em}%
    \begingroup
      \parindent \z@ \rightskip \@pnumwidth
      \parfillskip -\@pnumwidth
      \leavevmode %\bfseries
      \advance\leftskip\@tempdima
      \hskip -\leftskip
      #1\nobreak\Dotfill%\hfil
      \nobreak\hb@xt@\@pnumwidth{\hss #2}\par
     % \@dottedtocline{1}{1.5em}{2.3em}{#1}{#2}\par
      \penalty\@highpenalty
    \endgroup
  \fi}
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
\renewcommand*\l@section{\@dottedtocline{1}{4.25em}{2.3em}}
\renewcommand*\l@subsection{\@dottedtocline{2}{6.55em}{3.2em}}
\renewcommand*\l@subsubsection{\@dottedtocline{3}{10.75em}{4.1em}}
% \renewcommand{\numberline}[1]{\hb@xt@\@tempdima{#1\hfil}}
 \def\@chapter[#1]#2{ \ifnum \c@secnumdepth >\m@ne
                      \refstepcounter{chapter}%
                      \typeout{\@chapapp\space\thechapter.}%
                      %{\@chaptertype{} \protect\numberline{\thechapter}#1}%
                      %{\protect\numberline{\thechapter} #1}%
                      \ifnum\@appendix=0
                        \addcontentsline{toc}{chapter}{\hspace*{30pt}\protect\numberline{\Roman{chapter}} #1}%
                      \else
                        \addcontentsline{toc}{chapter}{\hspace*{30pt}\protect\numberline{\Alph{chapter}} #1}%
                      \fi
                    \else
                      %\addcontentsline{toc}{chapter}{\@chaptertype{} #1}
                      \addcontentsline{toc}{chapter}{\@chaptertype{} #1}
                    \fi
                    \ifnum\value{chapter}=1
                      \ifnum\@appendix=0
                        \pagestyle{\@textpagestyle}
                        \pagenumbering{\@textpagenumbering}
                      \fi
                    \fi
                    \chaptermark{#1}%
                    \addtocontents{lof}{\protect\addvspace{10\p@}}%
                    \addtocontents{lot}{\protect\addvspace{10\p@}}%
                    \if@twocolumn
                      \@topnewpage[\@makechapterhead{#2}]%
                    \else
                      \@makechapterhead{#2}%
                      \@afterheading
                    \fi
                    }
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Command from report.cls, (c) LaTeX3 Project.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 \def\@makechapterhead#1{%
  %\vspace*{-10\p@}%
  {\parindent\z@
    \@chapteralignment \reset@font
    \ifnum \c@secnumdepth >\m@ne
      %\LARGE\bfseries \@chapapp{} \thechapter
       %\bfseries \@chapapp{} \thechapter
       \ifnum\@appendix=0
         \bfseries \MakeUppercase\@chapapp{} \Roman{chapter}
       \else
         \bfseries \MakeUppercase\@chapapp{} \Alph{chapter}
       \fi
      \par
      \vskip 5\p@
    \fi
    %\LARGE\bfseries #1\par
    #1\par
    \nobreak
    \vskip 30\p@
  }}
 \def\@makeschapterhead#1{%
  \vspace*{2\p@}%
  {\parindent \z@ \@chapteralignment
    \reset@font
    %\LARGE \bfseries  #1\par
    \bfseries #1\par
    \nobreak
    \vskip 30\p@
  }}

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
%%% Command from report.cls, (c) LaTeX3 Project.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 \newdimen\bibindent
 \setlength\bibindent{1.5em}
 \pagestyle{\@textpagestyle}
 \renewenvironment{thebibliography}[1]
     { \chapter*{
        \vspace*{0.0cm}
        %{\Large\bibname}
        {\MakeUppercase\bibname}
        \@mkboth{\MakeUppercase\bibname}{\MakeUppercase\bibname}}%
      \setlength{\baselineskip}{30pt}

      \addcontentsline{toc}{chapter}{\MakeUppercase\bibname}
      \list{\@biblabel{\@arabic\c@enumiv}}%
           {\settowidth\labelwidth{\@biblabel{#1}}%
            \leftmargin\labelwidth
            \advance\leftmargin\labelsep
            \@openbib@code
            \usecounter{enumiv}%
            \let\p@enumiv\@empty
            \renewcommand\theenumiv{\@arabic\c@enumiv}}%
      \sloppy
      \clubpenalty4000
      \@clubpenalty \clubpenalty
      \widowpenalty4000%
      \sfcode`\.\@m}
     {\def\@noitemerr
       {\@latex@warning{Empty `thebibliography' environment}}%
      \endlist}


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Command to print draft version of the thesis.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 \newcommand{\thesisdraft}{
   \renewcommand{\@textpagestyle}{myheadings}
     \def\ps@myheadings{\let\@mkboth\@gobbletwo%
     \let\@oddfoot\@empty
      \def\@oddhead{\reset@font\hfil\thepage}
      \let\@evenfoot\@empty
      \let\@evenhead\@oddhead
    }
  \renewcommand\ps@empty{%
  \let\@mkboth\@gobbletwo
  \let\@oddfoot\@empty
  %\def\@oddhead{\reset@font\hfil$\;$}
  \let\@oddhead\@empty
  \let\@evenfoot\@empty
  \let\@evenhead\@oddhead
   }
  \renewcommand\ps@plain{\let\@mkboth\@gobbletwo
    \def\@oddhead{\reset@font\hfil$\;$}
    \def\@oddfoot{\reset@font\hfil\thepage\hfil}
    \let\@evenhead\@oddhead
    \let\@evenfoot\@oddhead
     }
    }
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Code to compute current timestamp.  Some parts by Martin Minow.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 \newcount\hour \newcount\minute
 \hour=\time  \divide \hour by 60 \minute=\time \loop \ifnum
 \minute > 59 \advance \minute by -60 \repeat
 \def\thesistime{\ifnum \hour<13 \number\hour:%
                      \ifnum \minute<10 0\fi
                      \number\minute
                      \ifnum \hour<12 \ am\else \ pm\fi
         \else \advance \hour by -12 \number\hour:%
                      \ifnum \minute<10 0\fi
                      \number\minute \ pm\fi}

 \def\DateOfDefense{\ifcase\month\or
 January\or February\or March\or April\or May\or June\or July\or
 August\or September\or October\or November\or December\fi
 \space\number\day, \number\year}

 \newcount\dow
 \newcount\leap
 \newcount\x
 \newcount\y

%leap = year + (month - 14)/12
 \leap=\month \advance\leap by -14 \divide\leap by 12
  \advance\leap by \year

%dow = (13 * (month + 10 - (month + 10)/13*12) - 1)/5
 \dow=\month \advance\dow by 10
  \y=\dow \divide\y by 13 \multiply\y by 12
  \advance\dow by -\y \multiply\dow by 13 \advance\dow by -1 \divide\dow by 5

%dow += day + 77 + 5 * (leap % 100)/4
 \advance\dow by \day \advance\dow by 77
  \x=\leap \y=\x \divide\y by 100 \multiply\y by 100 \advance\x by -\y
  \multiply\x by 5 \divide\x by 4 \advance\dow by \x

%dow += leap / 400
 \x=\leap \divide\x by 400 \advance\dow by \x

%dow -= leap / 100 * 2;
%dow = (dow % 7)
 \x=\leap \divide\x by 100 \multiply\x by 2 \advance\dow by -\x
  \x=\dow \divide\x by 7 \multiply\x by 7 \advance\dow by -\x

 \def\thesisdayofweek{\ifcase\dow
 Sunday\or Monday\or Tuesday\or Wednesday\or Thursday\or Friday\or
 Saturday\fi}

 \def\timestamp{\thesistime, \thesisdayofweek, \DateOfDefense}

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Commands for spacing.  Some parts from spacing.sty by Stephen Page.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
\ifx\undefined\selectfont
\def\@setsize#1#2#3#4{\@nomath#1
   \let\@currsize#1\baselineskip
   #2\baselineskip\baselinestretch\baselineskip
   \parskip\baselinestretch\parskip
   \setbox\strutbox\hbox{\vrule height.7\baselineskip
      depth.3\baselineskip width\z@}
   \normalbaselineskip\baselineskip#3#4}
\else
\def\@newbaseline{%
    \ifx\undefined\setnew@baselineskip
      \baselineskip\f@baselineskip\relax
    \else
      \setnew@baselineskip
    \fi
    \baselineskip\baselinestretch\baselineskip
    \setbox\strutbox\hbox{\vrule\@height.7\baselineskip
    \@depth.3\baselineskip \@width\z@}%
    \normalbaselineskip\baselineskip}
\fi
%%%
%%% Reset baselinestretch within footnotes and floats. Originally stolen
%%% from Stanford thesis style.
%%%
\def\@xfloat#1[#2]{\ifhmode \@bsphack\@floatpenalty -\@Mii\else
   \@floatpenalty-\@Miii\fi\def\@captype{#1}\ifinner
      \@parmoderr\@floatpenalty\z@
    \else\@next\@currbox\@freelist{\@tempcnta\csname ftype@#1\endcsname
       \multiply\@tempcnta\@xxxii\advance\@tempcnta\sixt@@n
       \@tfor \@tempa :=#2\do
                        {\if\@tempa h\advance\@tempcnta \@ne\fi
                         \if\@tempa t\advance\@tempcnta \tw@\fi
                         \if\@tempa b\advance\@tempcnta 4\relax\fi
                         \if\@tempa p\advance\@tempcnta 8\relax\fi
         }\global\count\@currbox\@tempcnta}\@fltovf\fi
    \global\setbox\@currbox\vbox\bgroup
    \def\baselinestretch{1}
    \ifx\undefined\selectfont
    \small\normalsize
    \else
    \@newbaseline
    \fi
    \boxmaxdepth\z@
    \hsize\columnwidth \@parboxrestore}
\long\def\@footnotetext#1{\insert\footins{\def\baselinestretch{1}\footnotesize
    \interlinepenalty\interfootnotelinepenalty
    \splittopskip\footnotesep
    \splitmaxdepth \dp\strutbox \floatingpenalty \@MM
    \hsize\columnwidth \@parboxrestore
   \edef\@currentlabel{\csname p@footnote\endcsname\@thefnmark}\@makefntext
    {\rule{\z@}{\footnotesep}\ignorespaces
      #1\strut}}}
%%%
%%% Stolen from MIT.
%%%
\def\spacing#1{\par%
 \begingroup
 \def\baselinestretch{#1}
 \ifx\undefined\selectfont
 \ifx\@currsize\normalsize\@normalsize\else\@currsize\fi
 \else
 \@newbaseline
 \fi}
\def\endspacing{\par
 \vskip \parskip
 \vskip \baselineskip
 \endgroup
 \vskip -\parskip
 \vskip -\baselineskip}

\renewcommand\section{\@startsection {section}{1}{\z@}%
                                   {-3.5ex \@plus -1ex \@minus -.2ex}%
                                   {2.3ex \@plus.2ex}%
                                   %{\normalfont\Large\bfseries}}
                                   {\normalfont\bfseries}}
\renewcommand\subsection{\@startsection{subsection}{2}{\z@}%
                                     {-3.25ex\@plus -1ex \@minus -.2ex}%
                                     {1.5ex \@plus .2ex}%
                                     {\normalfont\bfseries}}
\renewcommand\subsubsection{\@startsection{subsubsection}{3}{\z@}%
                                     {-3.25ex\@plus -1ex \@minus -.2ex}%
                                     {1.5ex \@plus .2ex}%
                                     {\normalfont\bfseries}}
 \newcounter{tbl}
 \setcounter{tbl}{0}
  \newcounter{fig}[chapter]
 \setcounter{fig}{0}
\renewcommand{\thefigure}
   {\thechapter.\@arabic\c@figure}
 \renewcommand{\thetable}
   {\thechapter.\@arabic\c@table}
\renewenvironment{figure}
               {\refstepcounter{fig}\@float{figure}}
               {\end@float}
\renewenvironment{figure*}
               {\refstepcounter{fig}\@dblfloat{figure}}
               {\end@dblfloat}
 \renewenvironment{table}
               {\refstepcounter{tbl}\@float{table}}
               {\end@float}
\renewenvironment{table*}
               {\refstepcounter{tbl}\@dblfloat{table}}
               {\end@dblfloat}
 \long\def\@makecaption#1#2{%
  \vskip\abovecaptionskip
  \sbox\@tempboxa{#1. #2}%
  \ifdim \wd\@tempboxa >\hsize
    #1. #2\par
  \else
    \global \@minipagefalse
    \hb@xt@\hsize{\hfil\box\@tempboxa\hfil}%
  \fi
  \vskip\belowcaptionskip}
