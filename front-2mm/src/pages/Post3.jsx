import React, { useState, useRef, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import styled from "styled-components";
import { useParams } from "react-router-dom";
import axios from "axios";

const Container = styled.div`
  position: relative;
  margin: 30px 0;
  max-width: 375px;
  height: 740px;
  background: white;
  border: 1px solid gray;
  margin: 30px auto;

  @media screen and (max-width: 768px) {
    width: 100%;
    padding-left: 0rem;
    padding-right: 0rem;
  }
`;

const Back = styled.div`
  position: relative;
  margin-top: 17px;
  margin-left: 15px;
`;

const Title = styled.div`
  position: relative;
  top: -23px;
  left: 170px;
`;

const ScrollBox = styled.div`
  height: 549px;
  overflow-y: auto;
  overflow-x: hidden;
  &::-webkit-scrollbar {
    /* WebKit 브라우저의 스크롤바를 숨김 */
    width: 0;
    background: transparent;
  }
`;

const CommentBox = styled.div`
  position: relative;
  height: 90px;
`;

const Profile = styled.div`
  position: relative;
  width: 50px;
  height: 50px;
  border-radius: 25px; /* 반지름을 width와 height의 절반으로 설정 */
  overflow: hidden; /* 이미지가 테두리를 넘어가지 않도록 설정 */
  top: 15px;
  left: 15px;
`;

const Name = styled.div`
  position: relative;
  color: #000;
  font-family: Inter;
  font-size: 16px;
  font-style: normal;
  font-weight: 700;
  line-height: normal;
  top: -33px;
  left: 75px;
`;

const CommentDetail = styled.div`
  position: relative;
  color: #0c0c0c;
  font-family: Inter;
  font-size: 22px;
  font-style: normal;
  font-weight: 400;
  line-height: normal;
  top: -35px;
  left: 73px;
`;

const Date = styled.div`
  position: relative;
  color: #0c0c0c;
  font-family: Inter;
  font-size: 12px;
  font-style: normal;
  font-weight: 400;
  line-height: normal;
  top: -90px;
  left: 200px;
`;

const VoiceBtn = styled.div`
  position: relative;
  height: 55px;
  width: 375px;
  top: 7px;
  cursor: pointer; /* 마우스 커서를 손가락 모양으로 변경 */
`;

const ChatBox = styled.div`
  position: relative;
  background: #efefef;
  top: 7px;
`;

const Chat = styled.input`
  position: relative;
  top: 11px;
  left: 10px;
  height: 15px;
  width: 74%; // 댓글 입력 창의 가로 크기를 조정합니다.
  padding: 12px 11px; // 좌우 패딩만 설정합니다.
  align-items: center;
  border-radius: 8px;
  background: #fff;
  border: none;

  ::placeholder {
    color: #434343;
  }
`;

const PostBtn = styled.div`
  position: relative;
  left: 325px;
  top: -19px;
`;

const Hr = styled.hr`
  position: relative;
  margin-top: -30px;
`;

const Post3 = () => {
  const navigate = useNavigate();
  const { postId } = useParams();
  const [comments, setComments] = useState([]); // 댓글 상태 변경

  const [recognizedText, setRecognizedText] = useState(""); // 음성으로 변환된 텍스트 상태
  const [isRecognizing, setIsRecognizing] = useState(false); // 음성 인식 중 여부 상태
  const [message, setMessage] = useState(""); // 메시지 상태
  const recognitionRef = useRef(null);

  // back_btn 이동
  const onClickBack = () => {
    navigate("/Post1");
  };

  // 음성 인식 코드
  const handleSpeechToText = () => {
    if ("webkitSpeechRecognition" in window) {
      console.log("음성인식을 지원하는 브라우저입니다.");
      recognitionRef.current = new window.webkitSpeechRecognition();
      recognitionRef.current.lang = "ko-KR";
      recognitionRef.current.interimResults = false;
      recognitionRef.current.maxAlternatives = 1;
      recognitionRef.current.maxDuration = 5000; // 5초로 설정

      recognitionRef.current.onstart = () => {
        console.log("음성인식이 시작되었습니다. 말씀해주세요.");
        setMessage("음성인식 시작...");
        setIsRecognizing(true);
      };

      recognitionRef.current.onspeechend = () => {
        setMessage("버튼을 누르고 아무 말이나 하세요.");
        setIsRecognizing(false);
      };

      recognitionRef.current.onresult = (event) => {
        const recognizedText = event.results[0][0].transcript;
        console.log("Recognized Text: ", recognizedText);
        setRecognizedText(recognizedText);
      };

      recognitionRef.current.onerror = (event) => {
        console.error("음성인식 오류 발생: ", event.error);
        setMessage("음성인식 중 오류가 발생했습니다.");
        setIsRecognizing(false);
      };

      recognitionRef.current.onend = () => {
        if (isRecognizing) {
          recognitionRef.current.start(); // isRecognizing이 true일 때만 다시 시작
        }
      };

      // 중지 후 시작
      recognitionRef.current.stop();
      recognitionRef.current.start();
    } else {
      console.log("음성인식을 지원하지 않는 브라우저입니다.");
      setMessage("음성인식을 지원하지 않는 브라우저입니다.");
    }
  };

  const handleVoiceBtnClick = () => {
    if ("webkitSpeechRecognition" in window) {
      handleSpeechToText();
    } else {
      console.log("음성인식을 지원하지 않는 브라우저입니다.");
      setMessage("음성인식을 지원하지 않는 브라우저입니다.");
    }
  };

  //post부분
  const onSubmit = async () => {
    try {
      console.log("Sending data:", recognizedText);

      const token = localStorage.getItem("token");
      const code = localStorage.getItem("code");

      const response = await axios
        .post(
          `http://127.0.0.1:8000/group/${code}/posts/${postId}/comments/`,
          {
            post: postId, // 포스트 ID를 포함시킵니다.
            comment: recognizedText, // 댓글 내용을 포함시킵니다.
          },
          {
            headers: {
              Authorization: `Token ${token}`,
              "Content-Type": "application/json",
            },
          }
        )
        .then(() => window.location.reload());

      console.log("Response data:", response.data);

      setRecognizedText("");
    } catch (error) {
      console.error("Error creating new post:", error);
      if (error.response) {
        console.log("Server response data:", error.response.data);
      }
    }
  };

  // get부분
  const [group, setGroup] = useState(null);

  useEffect(() => {
    const code = localStorage.getItem("code");
    const token = localStorage.getItem("token");

    const fetchData = async () => {
      try {
        const response = await axios.get(
          `http://127.0.0.1:8000/group/${code}/posts/${postId}/comments/`,
          {
            headers: {
              Authorization: `Token ${token}`,
              "Content-Type": "multipart/form-data",
            },
          }
        );

        console.log("Get Received data from API:", response.data);

        // 댓글 정보와 포스트 정보 추출
        const commentsData = response.data;
        console.log("Sample Comment Data:", commentsData[0]); // 댓글 데이터의 예시 출력

        // 댓글 정보와 포스트 정보 설정
        setComments(commentsData);
        setGroup("dummy_group"); // 임의의 그룹 정보를 설정 (실제로 사용할 그룹 정보로 대체)
      } catch (error) {
        console.error("Error fetching data:", error);
      }
    };
    fetchData();
  }, [postId]);

  if (!group) {
    return <div>Loading...</div>;
  }

  return (
    <Container>
      <Back onClick={onClickBack}>
        <img src={`${process.env.PUBLIC_URL}/images/back_btn.svg`} alt="back" />
      </Back>
      <Title>
        <img
          src={`${process.env.PUBLIC_URL}/images/post3_title.svg`}
          alt="title"
        />
      </Title>
      <ScrollBox>
        <CommentBox>
          {comments.map((comment) => (
            <div key={comment.id}>
              <Profile>
                <img
                  src={`http://127.0.0.1:8000${comment.writerProfile}`}
                  alt="Profile"
                  style={{ width: "100%", height: "100%", objectFit: "cover" }}
                />
              </Profile>
              <Name>{comment.writer}</Name>
              <CommentDetail>{comment.comment}</CommentDetail>
              <Date>{comment.createdAt}</Date>
              <Hr />
            </div>
          ))}
        </CommentBox>
      </ScrollBox>
      <VoiceBtn onClick={handleVoiceBtnClick}>
        <img
          src={`${process.env.PUBLIC_URL}/images/post3_btn.svg`}
          alt="post3_btn"
          style={{ width: "100%", height: "100%", objectFit: "cover" }}
        />
      </VoiceBtn>
      <ChatBox>
        <Chat
          placeholder="댓글을 입력하세요."
          value={recognizedText}
          onChange={(event) => setRecognizedText(event.target.value)}
        />
        <PostBtn onClick={onSubmit}>
          <img
            src={`${process.env.PUBLIC_URL}/images/comment_btn.svg`}
            alt="comment_btn"
          />
        </PostBtn>
      </ChatBox>
    </Container>
  );
};

export default Post3;
