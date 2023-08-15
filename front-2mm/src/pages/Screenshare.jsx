import React, { useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import styled from "styled-components";

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

const BoxZone = styled.div`
  position: relative;
  margin-top: 10px;
  margin-right: 5px;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
`;

const Title = styled.div`
  position: relative;
  margin-top: 30px;
`;

const SubTitle = styled.div`
  position: relative;
  margin-top: 40px;
`;

const CopyBox = styled.div`
  position: relative;
  margin-top: 20px;
  display: flex;
  max-width: 115px;
  max-height: 90px;
  padding: 19px 202px 49px 5px;
  align-items: center;
  flex-shrink: 0;
  border-radius: 6px;
  border: 1.5px solid #0085ff;
`;

const CopyBtn = styled.div`
  position: relative;
  margin-top: 20px;
  cursor: pointer;
`;

const NextBtn = styled.div`
  position: absolute; /* 위치를 absolute로 설정 */
  bottom: 30px;
  left: 50%; /* 가운데로 정렬하기 위해 왼쪽 위치 조정 */
  transform: translateX(-50%);
`;

const CopyAlert = styled.div`
  position: relative;
  margin-top: 10px;
  color: gray; /* 복사됨 텍스트의 색상 */
`;

const Screenshare = () => {
  const navigate = useNavigate();
  const [copied, setCopied] = useState(false);
  const copyBoxRef = useRef(null);

  const gotoProgress = () => {
    navigate("/ScreenProgress");
  };
  const gotoBack = () => {
    navigate("/GroupHome");
  };

  // copyBox에 뜰 url 가져오는 api추가 필요!!!

  const handleCopyClick = () => {
    if (copyBoxRef.current) {
      const range = document.createRange();
      range.selectNode(copyBoxRef.current);
      window.getSelection().removeAllRanges();
      window.getSelection().addRange(range);
      document.execCommand("copy");
      window.getSelection().removeAllRanges();
      setCopied(true);
      setTimeout(() => {
        setCopied(false);
      }, 2000); // 2초 후에 복사됨 상태 리셋
    }
  };

  return (
    <Container>
      <Back onClick={gotoBack}>
        <img src={`${process.env.PUBLIC_URL}/images/backbtn.svg`} />
      </Back>
      <BoxZone>
        <Title>
          <img src={`${process.env.PUBLIC_URL}/images/scrtitle.svg`} />
        </Title>
        <SubTitle>
          <img src={`${process.env.PUBLIC_URL}/images/explainscr.svg`} />
        </SubTitle>
        {/* url 받아오기!!!! get으로... */}
        <CopyBox ref={copyBoxRef}>
          https://us2mmweb/j/87528929085?pwd=yGaa9wUnpHu4Q8GIGlGRal8mYf7rkc.1
        </CopyBox>
        <CopyBtn onClick={handleCopyClick}>
          <img src={`${process.env.PUBLIC_URL}/images/copybtn.svg`} />
        </CopyBtn>
        {/* 복사 상태에 따라 텍스트를 표시하는 요소 */}
        <CopyAlert>{copied ? "주소가 복사되었습니다" : " "} </CopyAlert>
      </BoxZone>
      <NextBtn onClick={gotoProgress}>
        <img src={`${process.env.PUBLIC_URL}/images/sharestartbtn.svg`} />
      </NextBtn>
    </Container>
  );
};

export default Screenshare;
